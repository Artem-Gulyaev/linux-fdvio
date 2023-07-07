// SPDX-License-Identifier: GPL-2.0
//
// The loopback "remote processor" device to test the local rpmsg drivers.
//
// Copyright (C) 2023 Robert Bosch GmbH
//
// Artem Gulyaev
//

#define pr_fmt(fmt) "%s: line %d: " fmt, __func__, __LINE__

#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of_device.h>
#include <linux/rpmsg.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "rpmsg_internal.h"

//-------------------------------- ENUMS ------------------------------------//

// Dynamic name service announcement values.
//
// @RPMSG_NS_CREATE: a new remote service was just created
// @RPMSG_NS_DESTROY: a known remote service was just destroyed
enum rpmsg_ns_flags {
	RPMSG_NS_CREATE	= 0,
	RPMSG_NS_DESTROY = 1,
};

//------------------------ CONFIGURATION MACROS -----------------------------//

#define LBRP_DEV_NAME "lbrp"

// NOTE: here used only to simulate current restrictions on the
//  virtio rpmsg.
#define MAX_RPMSG_NUM_BUFS	(512)
#define MAX_RPMSG_BUF_SIZE	(512)

// Local addresses are dynamically allocated on-demand.
// We do not dynamically assign addresses from the low 1024 range,
// in order to reserve that address range for predefined services.
#define RPMSG_RESERVED_ADDRESSES	(1024)

// Address 53 is reserved for advertising remote services
#define RPMSG_NS_ADDR			(53)

//------------------------ FORWARD DECLARATIONS -----------------------------//

static void lbrp_rpmsg_destroy_ept(struct rpmsg_endpoint *ept);
static int lbrp_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len);
static int lbrp_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			       u32 dst);
static int lbrp_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
					u32 dst, void *data, int len);
static int lbrp_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len);
static int lbrp_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				  int len, u32 dst);
static int lbrp_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					   u32 dst, void *data, int len);

//-------------------------- HELPER MACROS ----------------------------------//

#define to_lbrp_rpmsg_channel_dev(_lbrp_ch_dev_ptr) \
	container_of(_lbrp_ch_dev_ptr, struct lbrp_rpmsg_channel_dev, rpdev)

//----------------------------- STRUCTS -------------------------------------//

// NOTE: here used only to simulate the size restrictions for the messages.
//
// common header for all rpmsg messages
// @src: source address
// @dst: destination address
// @reserved: reserved for future use
// @len: length of payload (in bytes)
// @flags: message flags
// @data: @len bytes of message payload data
//
// Every message sent(/received) on the rpmsg bus begins with this header.
struct rpmsg_hdr {
	u32 src;
	u32 dst;
	u32 reserved;
	u16 len;
	u16 flags;
	u8 data[0];
} __packed;

//
// struct rpmsg_ns_msg - dynamic name service announcement message
// @name: name of remote service that is published
// @addr: address of remote service that is published
// @flags: indicates whether service is created or destroyed
//
// This message is sent across to publish a new service, or announce
// about its removal. When we receive these messages, an appropriate
// rpmsg channel (i.e device) is created/destroyed. In turn, the ->probe()
// or ->remove() handler of the appropriate rpmsg driver will be invoked
// (if/as-soon-as one is registered).
//
struct rpmsg_ns_msg {
	char name[RPMSG_NAME_SIZE];
	u32 addr;
	u32 flags;
} __packed;

// entry of the announcements list to the "other side"
struct rpmsg_announcement_entry {
	struct list_head list_anchor;
    struct rpmsg_ns_msg msg;
};

// @list_anchor the anchor to embed the structure in the list
// @src the address of the source of this message
// @data the msg data
// @data_len_bytes data length in bytes
struct __lbrp_remote_ept_msg {
	struct list_head list_anchor;
    uint32_t src;
    char *data;
    size_t data_len_bytes;
};

// represents the remote endpoint 
// @addr own address of the endpoint
// @list_anchor the anchor to embed the structure in the list
// @msgs_head the head of the incoming messages list
// @msgs_lock the incoming messages list lock
// @sysfs_attr sysfs attribute, also contains the file name and file mode
// @service service to which the ept belongs.
struct __lbrp_remote_ept {
    uint32_t addr;
	struct list_head list_anchor;
	struct list_head rx_msgs_head;
	struct mutex rx_msgs_lock;
    struct attribute sysfs_attr;
	struct __lbrp_remote_service service;
};
 
// represents the remote service
// @kobj the kernel object accociated
//      NOTE: the parent object of this kobject is the lb_rpmsg_proc_dev
//              device.
// @list_anchor just as it is, to embed the service into a list of all
//      services.
// @name the service name
// @epts_head the head of the endpoints of the service (its own endpoints,
//      they have nothing to do with our local endpoints), the entries of
//      the list are __lbrp_remote_ept records.
// @epts_lock service own endpoints lock
//
// NOTE: IMPORTANT: each endpoint has a ref to its service,
//      when all endpoints got deleted, service automatically goes.
struct __lbrp_remote_service {
    struct kobject kobj;
	struct list_head list_anchor;
    char name[RPMSG_NAME_SIZE];
	struct list_head epts_head;
	struct mutex epts_lock;
};

// Describes the loopback rpmsg proc device.
// @dev our device node ptr.
// @endpoints set of local endpoints IDs (local addresses)
//     (all of them have the "remote" endpoint
//      counterpart as an rproc file in the sysfs).
// @endpoints_lock @endpoints modification lock
// @rpmsg_announcements the head of the announcements list
// @rpmsg_announcements_lock the protection lock for announcements
// @remote_services the list of the remote services (__lbrp_remote_service)
//      in action.
// @remote_services_lock the protection for the list of the
//      remote services.
struct lb_rpmsg_proc_dev {
	struct device *dev;
	struct idr endpoints;
	struct mutex endpoints_lock;
	struct list_head rpmsg_announcements;
	struct mutex rpmsg_announcements_lock;

	struct list_head remote_services;
	struct mutex remote_services_lock;
};

//
// The rpmsg channel representation (channel(service) device).
// Created separately for each new chanel being created.
// @rpdev the rp device.
// @lbrp_dev the remote processor device this channel accociated with.
struct lbrp_rpmsg_channel_dev {
	struct rpmsg_device rpdev;
    struct lb_rpmsg_proc_dev *lbrp_dev;
};

// Sysfs structure:
//
//      /create_ept   -> write to this file "your-service-name ADDR"
//                       to create the remote endpoint on the given service
//                       and given addr.
//
//                       NOTE: if the service does not exist then it will
//                          be created and announced.
//
//      /remove_ept   -> write to this file "your-service-name <ADDR>"
//                       to delete the remote endpoint from given service.
//
//                       NOTE: if no ADDR is given, all endpoints of the
//                          service will be removed.
//
//                       NOTE: if all endpoints of the service got removed,
//                          then the service removal will be announced and the
//                          service will be removed.
//
//      /announcements  -> read this file once to get single announcement
//                          sent to remote processor.
//
//      /SERVICE_NAME_DIR_1  -> represents a service
//          ./ept_ADDR1      -> represents a single remote endpoint
//                              you can RW this file to get/send messages
//                              through this endpoint.
//
//                              * to read one incoming message out of queue
//                                just read() on this ept, you will get
//                                the: 4 bytes of src addr +  raw payload
//
//                              * to write the message use write() with following
//                                format: 4 bytes of dst addr + raw payload.
//          ./ept_ADDR2
//          ...
//          ./ept_ADDRM
//      /SERVICE_NAME_DIR_2
//      ....
//      /SERVICE_NAME_DIR_N
//
// Overall structure:
//
//       READ/WRITE
//           V
//       sysfs file
//         service
//           |                          rpmsg client drivers
//           |                                   |
//           |                            rpmsg bus driver
//           |                                   |
//           |                              lbproc driver
//           \-----------------------------------/
//
// Devices structure:
//
//                            lbproc device
//                            /    |     \
//                           /     |      \
//                          /      |       \
//                         /       |        \
//                        /        |         \
//                       /         |          \
//                   ch 1         ch 2   ...   ch N
//             (child dev)    (child dev)   (child dev)
//             (rpmsg dev)    (rpmsg dev)   (rpmsg dev)
//
//
//             NOTE: all ch devices are registered on the rproc bus
//             NOTE: all channels are the struct lbrp_rpmsg_channel_dev which
//                  is "inherited" from rpmsg_device.

// service endpoints (attr) operations
const struct sysfs_ops __lbrp_service_sysfs_ops = {
	.show = __lbrp_service_ept_attr_show
	, .store = __lbrp_service_ept_attr_store
};

// defines the remote service object type
static const struct kobj_type remote_service_object_type {
        .release = &__lbrp_remove_remote_service_refcnt0
        , .sysfs_ops = &__lbrp_service_sysfs_ops,
};

static const struct rpmsg_device_ops lbrp_rpmsg_ops = {
	.create_ept = lbrp_rpmsg_create_ept,
	.announce_create = lbrp_rpmsg_announce_create,
	.announce_destroy = lbrp_rpmsg_announce_destroy,
};

static const struct rpmsg_endpoint_ops lbrp_endpoint_ops = {
	.destroy_ept = virtio_rpmsg_destroy_ept,
	.send = lbrp_rpmsg_send,
	.sendto = lbrp_rpmsg_sendto,
	.send_offchannel = lbrp_rpmsg_send_offchannel,
	.trysend = lbrp_rpmsg_trysend,
	.trysendto = lbrp_rpmsg_trysendto,
	.trysend_offchannel = lbrp_rpmsg_trysend_offchannel,
};

// Rpmsg on refcount->0 destructor.
// @kref: the ept's reference count
// Called automatically when refcount of ept reaches 0.
static void __ept_on_refcnt0(struct kref *kref)
{
	struct rpmsg_endpoint *ept = container_of(kref, struct rpmsg_endpoint,
						  refcount);
	kfree(ept);
}

// This function is called by rpmsg framework to create an actual
// endpoint (be it an initial channel endpoint or additional endpoints).
//
// See the rpmsg_create_ept() description for more info.
// @rpdev the channel device to add the ept to.
// @cb callback to accociate with ept.
// @priv the private pointer to pass to callback.
// @chinfo the channel info to create the endpoint for.
static struct rpmsg_endpoint *lbrp_rpmsg_create_ept(
        struct rpmsg_device *rpdev
		, rpmsg_rx_cb_t cb
		, void *priv
		, struct rpmsg_channel_info chinfo)
{
	struct lbrp_rpmsg_channel_dev *lbrp_ch = to_lbrp_rpmsg_channel_dev(rpdev);

	return __lbrp_rpmsg_create_ept(lbrp_ch->lbrp_dev, rpdev, cb
                                   , priv, chinfo.src);
}

// Implements the contract of the rpmsg_create_ept() (see rpmsg documentation).
//
// @lbrp our main device
// @rpdev the pointer to the channel device
// RETURNS:
//      NULL: in case of error
//      else: valid ptr to new endpoint
static struct rpmsg_endpoint *__lbrp_rpmsg_create_ept(
                struct lb_rpmsg_proc_dev *lbrp
				, struct rpmsg_device *rpdev
				, rpmsg_rx_cb_t cb
				, void *priv
                , u32 local_addr)
{
	struct device dev = rpdev ? &rpdev->dev : lbrp->dev;

	struct rpmsg_endpoint *ept = NULL;
	ept = kzalloc(sizeof(*ept), GFP_KERNEL);
	if (!ept) {
		dev_err(dev, "EPT allocation failed, no memory.\n");
		return NULL;
    }

	kref_init(&ept->refcount);
	mutex_init(&ept->cb_lock);

	ept->rpdev = rpdev;
	ept->cb = cb;
	ept->priv = priv;
	ept->ops = &lbrp_endpoint_ops;

    // Recommended way for client drivers to avoid fixed allocation
	int id_min = RPMSG_RESERVED_ADDRESSES;
    int id_max = 0;
	if (local_addr != RPMSG_ADDR_ANY) {
		id_min = local_addr;
		id_max = local_addr + 1;
	}

	mutex_lock(&lbrp->endpoints_lock);

	// allocating the free local address
	int id = idr_alloc(&lbrp->endpoints, ept, id_min, id_max, GFP_KERNEL);
	if (id < 0) {
		dev_err(dev, "idr_alloc failed: %d\n", id);
		goto free_ept;
	}
	ept->local_addr = id;

	mutex_unlock(&lbrp->endpoints_lock);

	return ept;

free_ept:
	mutex_unlock(&lbrp->endpoints_lock);
	kref_put(&ept->refcount, __ept_on_refcnt0);
	return NULL;
}

// Removes existing rpmsg endpoint from our device (ept should not be bound
// to the channel already). Drop its refcount.
// If endpoint ref counter reaches 0 it will surely also delete it.
// @lbrp our main "remote" proc device.
// @ept endpoint to close
static void
__rpmsg_remove_ept(struct lb_rpmsg_proc_dev *lbrp, struct rpmsg_endpoint *ept)
{
	mutex_lock(&lbrp->endpoints_lock);
	idr_remove(&lbrp->endpoints, ept->addr);
	mutex_unlock(&lbtp->endpoints_lock);

	mutex_lock(&ept->cb_lock);
	ept->cb = NULL;
	mutex_unlock(&ept->cb_lock);

	kref_put(&ept->refcount, __ept_on_refcnt0);
}

// Gets called by the rpmsg framework when the destruction of the
// endpoint is requested.
// @ept the endpoint ptr.
static void virtio_rpmsg_destroy_ept(struct rpmsg_endpoint *ept)
{
	struct lbrp_rpmsg_channel_dev *lbrp_ch
                = to_lbrp_rpmsg_channel_dev(ept->rpdev);

	__rpmsg_remove_ept(lbrp_ch->lbrp_dev, ept);
}

// Get's triggered whenever from
// userspace one wants to write the sysfs file create_ept file. It creates
// a new remote endpoint for the rpmsg.
//
// NOTE: if the remote service doesn't exist yet, it gets created
//      and announced to local rpmsg.
//
// WRITE FORMAT:  "your-service-name ADDR"
//
//  * your-service-name - a string with no spaces
//  * single space
//  * ADDR - the int32_t the address of the remote endpoint
// 
// @dev {valid ptr} device, which has the driver data->lb_rpmsg_proc_dev
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//         count: ok
//         <0: negated error code
static ssize_t create_ept_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
    char *service_name = strim(strsep(buf, " "));
    char *addr_str = strim(buf);

    if (IS_ERR_OR_NULL(addr_str) || IS_ERR_OR_NULL(service_name)) {
        goto wrong_usage;
    }

    if (strlen(service_name) >= RPMSG_NAME_SIZE) {
        dev_err(dev, "Too long service name: must be <= %d"
                , RPMSG_NAME_SIZE - 1)
        goto wrong_usage;
    }

    uint32_t remote_addr;
    if (kstrtou32(addr_str, 0, &remote_addr)) {
        goto wrong_usage;
    }

    struct lb_rpmsg_proc_dev *lbrp
	        = (struct b_rpmsg_proc_dev *)dev_get_drvdata(dev);
    if (IS_ERR_OR_NULL(lbrp)) {
        dev_err(dev, "Sorry, no lbrp dev referenced by the dev.");
        goto error;
    }

    bool channel_existed = false;
    // NOTE: service will have refcount ++ after this call.
    struct __lbrp_remote_service *rservice = __lbrp_create_remote_service(
                                                     lbrp, name
                                                     , &channel_existed);

    if (IS_ERR_OR_NULL(rservice)) {
        dev_err(dev, "Failed to find/create service with name %s.", name);
        goto error;
    }

    struct __lbrp_remote_ept *ept = __lbrp_create_remote_ept(
                rservice, remote_addr);

    if (IS_ERR_OR_NULL(ept)) {
        __lbrp_put_remote_service(rservice);
        goto error;
    }

    // endpoint holds a ref to the service, from now on
    __lbrp_put_remote_service(rservice);

    // if the channel was just created, then we notify the "other" side
    // about its creation ("other" means local in this case)
    if (!channel_existed) {
        struct rpmsg_ns_msg msg;
        strncpy(msg.name, service_name, sizeof(msg.name));
        msg.addr = remote_addr;
        msg.flags = RPMSG_NS_CREATE;

        lb_rpmsg_service_ctl(lbrp, &msg);
    }

	return count;

wrong_usage:
	dev_err(dev,
            "Adds the given endpoint to the service in sysfs.\n"
            "WRITE FORMAT:  \"your-service-name ADDR\"\n"
            " * your-service-name - a string with no spaces (max len: %d)\n"
            " * single space\n"
            " * ADDR - the int32_t the address of the remote endpoint\n"
            , RPMSG_NAME_SIZE - 1);
    return -EINVAL;

error:
	return -EFAULT;
}
static DEVICE_ATTR_WO(create_ept);

// Get's triggered whenever from userspace one wants to write the sysfs
// file remove_ept file. It removes given endpoint from given service.
//
// NOTE: if the remote service or endpoint doesn't exist, no error.
//
// NOTE: if this is a last endpoint of the service it will be removed
//      automatically.
//
// WRITE FORMAT:  "your-service-name ADDR"
//
//  * your-service-name - a string with no spaces
//  * single space
//  * ADDR - the int32_t the address of the remote endpoint
// 
// @dev {valid ptr} device, which has the driver data->lb_rpmsg_proc_dev
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to read input from userspace
// @count {number} the @buf string length not-including the  0-terminator
//                 which is automatically appended by sysfs subsystem
//
// RETURNS:
//         count: ok
//         <0: negated error code
static ssize_t remove_ept_store(
		struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
    char *service_name = strim(strsep(buf, " "));
    char *addr_str = strim(buf);

    if (IS_ERR_OR_NULL(addr_str) || IS_ERR_OR_NULL(service_name)) {
        goto wrong_usage;
    }

    if (strlen(service_name) >= RPMSG_NAME_SIZE) {
        dev_err(dev, "Too long service name: must be <= %d"
                , RPMSG_NAME_SIZE - 1)
        goto wrong_usage;
    }

    uint32_t remote_addr;
    if (kstrtou32(addr_str, 0, &remote_addr)) {
        goto wrong_usage;
    }

    struct lb_rpmsg_proc_dev *lbrp
	        = (struct b_rpmsg_proc_dev *)dev_get_drvdata(dev);
    if (IS_ERR_OR_NULL(lbrp)) {
        dev_err(dev, "Sorry, no lbrp dev referenced by the dev.");
        goto error;
    }

    // NOTE: increments service refcount
    struct __lbrp_remote_service *service
                    = __lbrp_get_remote_service(lbrp, service_name);

    if (!service) {
        dev_info(dev, "Service %s already doesn't exist.", name);
        return count;
    }

    __lbrp_remove_remote_ept(service, remote_addr, true);

    // dropping our own ref to service
    __lbrp_put_remote_service(rservice);
	return count;

wrong_usage:
	dev_err(dev,
            "Removes the given endpoint from sysfs.\n"
            "WRITE FORMAT:  \"your-service-name ADDR\"\n"
            " * your-service-name - a string with no spaces (max len: %d)\n"
            " * single space\n"
            " * ADDR - the int32_t the address of the remote endpoint\n"
            , RPMSG_NAME_SIZE - 1);
    return -EINVAL;

error:
	return -EFAULT;
}
static DEVICE_ATTR_WO(remove_ept);

// Endpoint file read operation.
//
//     * to read one incoming message out of queue
//       just read() on this ept, you will get
//       the: 4 bytes of src addr +  raw payload
static ssize_t __lbrp_service_ept_attr_show(
				struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct __lbrp_remote_ept *rept
				= container_of(attr, struct __lbrp_remote_ept, sysfs_attr);
	struct lb_rpmsg_proc_dev *lbrp = __lbrp_from_rservice(rept->service);
	struct __lbrp_remote_ept_msg *msg = __lbrp_remote_ept_pop_rx_msg(rept);

	if (!msg) {
		return 0;
	}
    if (sizeof(msg->src) + msg->data_len_bytes > PAGE_SIZE) {
        def_err(lbrp->dev, "too big message to show via sysfs: "
                "len: %d, source: %d\n", msg->data_len_bytes
                , msg->src);
	    __lbrp_remote_ept_destroy_rx_msg(msg);
        return 0;
    }

	ssize_t len = 0;

	// 4 bytes of the source addr
	*((uint32_t *)buf) = msg->src;
	len += sizeof(msg->src);


	// the data itself
	memcpy(buf + len, msg->data, msg->data_len_bytes);
	len += msg->data_len_bytes;

	__lbrp_remote_ept_destroy_rx_msg(msg);

	return len;
}

// Endpoint file write operation.
//
//     * to write the message use write() with following
//       format: 4 bytes of dst addr + raw payload.
static ssize_t __lbrp_service_ept_attr_store(
				struct kobject *kobj, struct attribute *attr
			    , const char *buf, size_t count)
{
	struct __lbrp_remote_ept *rept
				= container_of(attr, struct __lbrp_remote_ept, sysfs_attr);
	struct lb_rpmsg_proc_dev * lbrp = __lbrp_from_rservice(rept->service);

	if (count <= sizeof(uint32_t)) {
		dev_warn(dev, "to small message, len: %d\n", count);
		goto usage;
	}

	uint32_t msg_len = count - sizeof(uint32_t);
	char *msg_data = buf + sizeof(uint32_t);
	// first 4 bytes of destination
	uint32_t dst = *((uint32_t *)buf);

	// to match the virtio logic
	if (msg_len > MAX_RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr)) {
		dev_warn(dev, "inbound msg too big: (%d, %d)\n", len, msg->len);
		return -EINVAL;
	}

	dev_dbg(lbrp->dev, "From: 0x%x, To: 0x%x, Len: %d, (userspace len: %d)\n"
			, rept->addr, dst, msg_len, count);
#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("lbrp RX: ", DUMP_PREFIX_NONE, 16, 1
			 		 , msg_data, msg_len, true);
#endif

	mutex_lock(&lbrp->endpoints_lock);
	struct rpmsg_endpoint *ept = idr_find(&lbrp->endpoints, dst);
	if (ept) {
		kref_get(&ept->refcount);
	}
	mutex_unlock(&lbrp->endpoints_lock);

    // And actually deliver the message to local consumer
	if (ept) {
		mutex_lock(&ept->cb_lock);
		if (ept->cb) {
			ept->cb(ept->rpdev, msg_data, msg_len, ept->priv, rept->addr);
            // NOTE: the data buffer will not be used by consumer
            //      after callback is returned.
        }
		mutex_unlock(&ept->cb_lock);

		kref_put(&ept->refcount, __ept_on_refcnt0);
	} else {
		dev_warn(dev, "msg received with no recipient\n");
    }

	return count;

usage:
	dev_err(lbrp->dev, "Write format is: 4 bytes of dst addr + raw payload.\n"
                       "  NOTE: min payload length is: %d\n"
                       "  NOTE: max payload length is: %d\n"
            , 1, MAX_RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr));
	return -EINVAL;
}

// Creates/gets an endpoint with given own address for the given service.
// NOTE: if endpoint already exists is is not an error.
// @service the service to attach endpoint to.
// @own_address the own address of endpoint to find/create.
//
// NOTE: when successfull, increments the refcount of the service
//
// RETURNS:
//      !NULL: newly created or found endpoint
//      NULL: if error occured
struct __lbrp_remote_ept *__lbrp_create_remote_ept(
            struct __lbrp_remote_service *service
            , uint32_t own_address)
{
    if (IS_ERR_OR_NULL(service)) {
        pr_err("No service to add ept.");
        return NULL;
    }

    struct lb_rpmsg_proc_dev * lbrp = __lbrp_from_rservice(service);

    if (IS_ERR_OR_NULL(lbrp)) {
        pr_err("No lbrp to work with.");
        return NULL;
    }

    struct __lbrp_remote_ept *ept;
    ept = kzalloc(sizeof(*ept), GFP_KERNEL);
    if (IS_ERR_OR_NULL(ept)) {
        dev_err(lbrp->dev, "no memory for new remote endpoint");
        goto malloc_failed;
    }

    ept->addr = own_address;

    ssize_t name_size = snprintf(NULL, 0, "ept_%d", ept->addr) + 1;
    ept->sysfs_attr.name = kmalloc(name_size, GFP_KERNEL);
    if (IS_ERR_OR_NULL(ept->sysfs_attr.name)) {
        dev_err(lbrp->dev, "no memory for ept name");
        goto file_name_malloc_failed;
    }
    snprintf(ept->sysfs_attr.name, name_size, "ept_%d", ept->addr);
    ept->sysfs_attr.mode = 0660;

    INIT_LIST_HEAD(&ept->list_anchor);
    INIT_LIST_HEAD(&ept->rx_msgs_head);
    mutex_init(&ept->rx_msgs_lock);
    ept->service = service;

    mutex_lock(&service->epts_lock);
    struct __lbrp_remote_ept *te = NULL;
    list_for_each_entry(te, &service->epts_head, list_anchor) {
        if (te->addr == own_address) {
            mutex_unlock(&service->epts_lock);
            dev_warn(lbrp->dev, "remote endpoint for service %s and addr %d"
                                " already exists.", service->name, own_address);
            goto already_exists;
        }
    }
    list_add_tail(&ept->list_anchor, &service->epts_head);
    mutex_unlock(&service->epts_lock);

    int res = sysfs_create_file(service->kobj, &ept->sysfs_attr);
    if (res != 0) {
        dev_err(lbrp->dev, "failed to create ept attr: %s", ept->sysfs_attr.name);
        goto sysfs_create_failed;
    }

    // don't allow anyone to delete the service while it has
    // endpoints
    __lbrp_get_remote_service_by_ptr(service);

    return ept;

sysfs_create_failed:
    mutex_lock(&service->epts_lock);
    list_del(&ept->list_anchor);
    mutex_unlock(&service->epts_lock);
already_exists:
    mutex_destroy(&ept->rx_msgs_lock);
    free(ept->sysfs_attr.name);
file_name_malloc_failed:
    free(ept);
malloc_failed:
    return NULL;
}

// Removes the remote endpoint from the service.
// @service to work with
// @own_address the endpoint-to-remove own address
// @list_lock_needed if true then the service list lock will be used
//      (needed for single ept deletion). If false then no locking
//      will be done on service->epts_lock (needed when deleting many
//      or all endpoints in selfconsistent manner).
void __lbrp_remove_remote_ept(
            struct __lbrp_remote_service *service
            , uint32_t own_address
            , const bool list_lock_needed)
{
    struct lb_rpmsg_proc_dev * lbrp = __lbrp_from_rservice(service);

    dev_info(lbrp->dev, "removing ept %d of %s service"
             , own_address, service->name);

    // drop it from the service list, so no incoming messages
    // will be appended to the ept messages

    if (list_lock_needed) {
        mutex_lock(&service->epts_lock);
    }

    struct __lbrp_remote_ept *ept = NULL;
    list_for_each_entry(ept, &service->epts_head, list_anchor) {
        if (ept->addr == own_address) {
            break;
        }
    }
    if (list_entry_is_head(ept, &service->epts_head, list_anchor)) {
        if (list_lock_needed) {
            mutex_unlock(&service->epts_lock);
        }
        dev_warn("ept %d of %s service already doesn't exist"
                 , own_address, service->name);
        return;    
    }

    list_del(&ept->list_anchor);

    if (list_lock_needed) {
        mutex_unlock(&service->epts_lock);
    }

    // now we will remove the corresponding sysfs file
    sysfs_remove_file(&service->kobj, &ept->sysfs_attr);
    free(ept->sysfs_attr.name);

    // now we will drop all pending messages of this ept 

    mutex_lock(&ept->rx_msgs_lock);

    struct __lbrp_remote_ept_msg *msg;
    while (msg = list_first_entry_or_null(&ept->rx_msgs_head)) {
        list_del(&msg->list_anchor);
        
        __lbrp_remote_ept_destroy_rx_msg(msg);
    }
    
    mutex_unlock(&ept->rx_msgs_lock);

    // now removing the ept itself

    mutex_destroy(&ept->rx_msgs_lock);
    free(ept);

    dev_info(lbrp->dev, "removed ept %d of %s service"
             , own_address, service->name);

    // if this was the last endpoint of the service, the service also leaves.
    __lbrp_put_remote_service(service);
}

// Adds the rx message to the list of RX messages (pending to be read
// by userland from sysfs) of the remote endpoint.
// @ept the remote endpoint to work with.
// @data raw data to push as message
//      NOTE: this data is copied
// @data_len_bytes size of @data in bytes.
// @msg_src the source addr of the message.
//
// RETURNS:
//      NULL: didn't make it
//      else: valid pointer to newly added msg
struct __lbrp_remote_ept_msg *__lbrp_remote_ept_push_rx_msg(
        struct __lbrp_remote_ept *ept
        , char *data, size_t data_len_bytes
        , uint32_t msg_src)
{
    struct __lbrp_remote_ept_msg *msg = NULL;
    msg = kzalloc(sizeof(*msg), GFP_KERNEL);
    if (IS_ERR_OR_NULL(msg)) {
        goto struct_alloc_f;
    }

    INIT_LIST_HEAD(&msg->list_anchor);
    msg->src = msg_src;

    msg->data = kzalloc(data_len_bytes, GFP_KERNEL);
    if (IS_ERR_OR_NULL(msg->data)) {
        goto data_alloc_f;
    }
    memcpy(msg->data, data, data_len_bytes);
    msg->data_len_bytes = data_len_bytes;

    // now adding the msg to ept (end of list for FIFO mode)

    mutex_lock(&ept->rx_msgs_lock);
    list_add_tail(&ept->rx_msgs_head);
    mutex_unlock(&ept->rx_msgs_lock);

    return msg;

data_alloc_f:
    free(msg);
struct_alloc_f:
    return NULL;
}

// Send a message across to the "remote" processor.
// @rpdev: the rpmsg channel
// @src: source address
// @dst: destination address
// @data: payload of message
// @len: length of payload
// @wait: indicates whether caller should block if operation needs to wait.
//
// This function is the base implementation for all of the rpmsg sending API.
//
// It will send @data of length @len to @dst, and say it's from @src. The
// message will be sent to the "remote" processor which the @rpdev channel
// belongs to.
//
// The message is sent using one of the TX buffers that are available for
// communication with this remote processor.
//
// RETURNS:
//      0: on success,
//      <0: negated error value on failure.
static int lbrp_send_offchannel_raw(struct rpmsg_device *rpdev,
				     u32 src, u32 dst,
				     void *data, int len, bool wait)
{
	struct lbrp_rpmsg_channel_dev *lbrp= to_lbrp_rpmsg_channel_dev(rpdev);
	struct device *dev = lbrp->dev;

	// we can do broadcasting actually, but as long as native rpmsg
    // over virtio doesn't suppor this, we also will not support for now
	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%x, dst 0x%x): no broadcasting"
                " allowed\n", src, dst);
		return -EINVAL;
	}

    // same reason for the msg size limit: rpmsg over virtio supports
    // only up to MAX_RPMSG_BUF_SIZE now is 512 bytes messages.
	if (len > MAX_RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr)) {
		dev_err(dev, "message is too big (%d), must be <= %d\n", len
                , MAX_RPMSG_BUF_SIZE - sizeof(struct rpmsg_hdr));
		return -EMSGSIZE;
	}

    // find the service and endpoint for the dst

    struct __lbrp_remote_service *rservice;
    struct __lbrp_remote_ept *rept;

	mutex_lock(&lbrp->remote_services_lock);

    list_for_each_entry(rservice, &lbrp->remote_services, list_anchor) {
	    mutex_lock(&rservice->epts_lock);
        list_for_each_entry(rept, &rservice->epts_head, list_anchor) {
            if (rept->addr == dst) {
                // prevent service from going away
                __lbrp_get_remote_service_by_ptr(rservice);
	            mutex_unlock(&lbrp->remote_services_lock);
                goto found;
            }
        }
	    mutex_unlock(&rservice->epts_lock);
    }

    // remote endpoint was not found
	mutex_unlock(&lbrp->remote_services_lock);
    // this is not an error, actually
    return 0;

found:
    // NOTE: we keep the endpoints lock here
    //      so, no one will try to remove it meanwhile

    int res = 0;
    if (__lbrp_remote_ept_push_rx_msg(rept, data, len, src) == NULL) {
        dev_err(lbrp->dev, "Failed to push the message to remote endpoint:"
                " TX From 0x%x, To 0x%x, Len %d", src, dst, len);
        res = -1;
    };

	mutex_unlock(&rservice->epts_lock);

    if (res == 0) {
        dev_dbg(dev, "TX From 0x%x, To 0x%x, Len %d\n", src, dst, len);
#if defined(CONFIG_DYNAMIC_DEBUG)
        dynamic_hex_dump("lbrp_rpmsg TX: ", DUMP_PREFIX_NONE, 16, 1
                         , data, len, true);
#endif
    }

    __lbrp_put_remote_service(rservice);

	return res;
}

static int lbrp_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return lbrp_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int lbrp_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			       u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return lbrp_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int lbrp_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
					u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return lbrp_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int lbrp_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return lbrp_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int lbrp_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				  int len, u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return lbrp_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int lbrp_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					   u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return lbrp_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

// Pops the first pending message out of the RX pending queue (toward the
// sysfs). It removes it from pending list, but doesn't destroy.
// You need to call __lbrp_remote_ept_destroy_rx_msg(...) to destroy it later.
// @ept endpoint to work with.
//
// RETURNS: the first message in rx queue, or NULL
struct __lbrp_remote_ept_msg *__lbrp_remote_ept_pop_rx_msg(
        struct __lbrp_remote_ept *ept)
{
    mutex_lock(&ept->rx_msgs_lock);

    struct __lbrp_remote_ept_msg *msg
                = list_first_entry_or_null(&ept->rx_msgs_head
                                           , struct __lbrp_remote_ept_msg
                                           , list_anchor);
    if (msg) {
        list_del(&msg->list_anchor);
    }

    mutex_unlock(&ept->rx_msgs_lock);

    return msg;
}

// Actually destroys the remote rx message.
// NOTE: the message must be already removed from any lists already.
// @msg the message to delete.
void __lbrp_remote_ept_destroy_rx_msg(struct __lbrp_remote_ept_msg *msg)
{
    if (IS_ERR_OR_NULL(msg)) {
        return;
    }

    msg->data_len_bytes = 0;
    free(msg->data);
    free(msg);
}

// Tries to find remote service.
// NOTE: increments the service refcount
//
// RETURNS:
//      !NULL: the remote service pointer
//      NULL: if service was not found
struct __lbrp_remote_service *__lbrp_get_remote_service(
            struct lb_rpmsg_proc_dev *lbrp
            , char *name)
{
    mutex_lock(&lbrp->remote_services_lock);
    struct __lbrp_remote_service *rservice = NULL;
    list_for_each_entry(rservice, &lbrp->remote_services, list_anchor) {
        if (strncmp(name, rservice->name, sizeof(rservice->name)) == 0) {
            break;
        }
    }
    if (rservice) {
        __lbrp_get_remote_service_by_ptr(service);
    }
    mutex_unlock(&lbrp->remote_services_lock);
    return rservice;
}

// Decrement refcounter of the service.
void __lbrp_put_remote_service(
            struct __lbrp_remote_service *service)
{
    kobject_put(&rservice->kobj);
}

// increment the service refcount
void __lbrp_get_remote_service_by_ptr(
            struct __lbrp_remote_service *service)
{
    kobject_get(&service->kobj);
}

// Creates the remote service record for the lbrp. If service
// already exists - all fine, no error. New service has no own endpoints.
// @lbrp our device.
// @name the remote service name to create.
// @existed__out set to true if channel existed.
//
// NOTE: after this call the refcount of the service is incremented
//    (to 1 for new services, and x++ for existing) (if it succeeded).
//
// LOCKING: does all locking itself.
//
// RETURNS:
//      the ptr to existing or newly created remote service: if all fine
//      NULL: if something went wrong
struct __lbrp_remote_service *__lbrp_create_remote_service(
            struct lb_rpmsg_proc_dev *lbrp
            , char *name
            , bool *existed__out)
{
    dev_info(lbrp->dev, "Creating remote service: %s", name);

    // check if service is there already
    struct __lbrp_remote_service *rservice
                = __lbrp_get_remote_service(lbrp, name);
    if (rservice) {
        if (existed__out) {
            *existed__out = true;
        }

        return rservice;
    }

    // need to create a new one
    rservice = kzalloc(sizeof(*rservice), GFP_KERNEL);
    if (IS_ERR_OR_NULL(rservice)) {
        dev_err(lbrp->dev, "no memory for new remote service");
        return NULL;
    }

    strncpy(&rservice.name[0], name, sizeof(rservice.name));
    if (rservice.name[sizeof(rservice.name) - 1] != 0) {
        dev_err(lbrp->dev, "name is too big, must fit into %d chars"
                , sizeof(rservice.name));
        free(rservice);
        return NULL;
    }

    mutex_init(&rservice->epts_lock);
    INIT_LIST_HEAD(&rservice->epts_head);
    INIT_LIST_HEAD(&rservice->list_anchor);

    mutex_lock(&lbrp->remote_services_lock);

    kobject_init(&rservice->kobj, &remote_service_object_type);

    list_add_tail(&rservice->list_anchor, &lbrp->remote_services);

    int res = kobject_add(&rservice->kobj, &lbrp->dev->kobj, "%s", name);
    if (res != 0) {
        dev_err(lbrp->dev, "failed to add remote service, err: %d", res);
        __lbrp_put_remote_service(rservice);
        rservice = NULL;
    }

    mutex_unlock(&lbrp->remote_services_lock);

    return rservice;
}

// Removes the remote service
// Also drops it from the remote services list of the lbrp.
//
// NOTE: MUST BE CALLED ONLY FROM DESTRUCTOR, don't call it directly!
//
// @kobject the pointer to the kobj of the service.
// @name name of the service to remove
void __lbrp_remove_remote_service_refcnt0(struct kobject *kobject)
{
    struct __lbrp_remote_service *service
        = container_of(kobject, struct __lbrp_remote_service, kobj);

    struct lb_rpmsg_proc_dev *lbrp = __lbrp_from_rservice(service);

    if (IS_ERR_OR_NULL(lbrp)) {
        pr_err("Can't remove service: no device.");
        return;
    }
    dev_info(lbrp->dev, "Removing remote service: %s", name);

    // Then dropping service from the lbrp services list

    mutex_lock(&lbrp->remote_services_lock);

    struct __lbrp_remote_service *service = NULL;
    list_for_each_entry(service, lbrp->remote_services, list_anchor) {
        if (strncmp(service->name, name, sizeof(service->name)) == 0) {
            break;
        }
    }
    if (list_entry_is_head(service, lbrp->remote_services, list_anchor)) {
        mutex_unlock(&service->epts_lock);
        dev_warn(lbrp->dev, "No service named: %s", name);
        return;
    }

    list_del(&service->list_anchor);

    // Notifying the "other" side about service removal

    {
        struct rpmsg_ns_msg msg;
        strncpy(msg.name, service->name, sizeof(msg.name));
        msg.addr = RPMSG_ADDR_ANY;
        msg.flags = RPMSG_NS_DESTROY;

        lb_rpmsg_service_ctl(lbrp, &msg);
    }

    // NO need to remote endpoints, cause we can be released only
    // when endpoints are destroyed alreay.

    mutex_lock(&service->epts_lock);
    struct __lbrp_remote_ept *ept = list_first_entry_or_null(&service->epts_head);
    if (ept) {
        dev_err(lbrp->dev, "Service destroyed while there were endpoints.")
    }
    mutex_unlock(&service->epts_lock);

    mutex_destroy(&service->epts_lock);

    dev_info(lbrp->dev, "removed remote service: %s", service.name);

    free(service);

    mutex_unlock(&lbrp->remote_services_lock);
}

// RETURNS: the lbrp device for given remote service
struct lb_rpmsg_proc_dev * __lbrp_from_rservice(struct __lbrp_remote_service *rs)
{
    struct device *lbrp_dev = container_of(rs->kobj->parent, struct device, kobj);
    return (struct lb_rpmsg_proc_dev *)dev_get_drvdata(lbrp_dev);
}

// Creates/destroys the service (channel) associated with the
// loopback processor provided by the data of the rpmsg_ns_msg which is
// normally used to announce remote services to the driver.
// NOTE: the address of local endpoint will be selected automatically
//      among available and then the corresponding client driver will be
//      probed using the service name.
// NOTE: in general case the remote counterpart will get the address
//      of local enpoint when we send the data to it for the first time (it
//      will be stated as src address of the msg).
// NOTE: this guy is called when the new service announcement arrives
//      from "remote" (in our case when a new service is created in
//      sysfs by user app).
//
// @lbrp our device to work with
// @msg service (channel) announcement info
//
// RETURNS:
//      0: all fine
//      <0: negated error code
static int lb_rpmsg_service_ctl(
            struct lb_rpmsg_proc_dev *lbrp
	        , struct rpmsg_ns_msg *msg)
{
	struct device *dev = lbrp->dev;

	dev_info(dev, "%sing lbrp channel \"%s\", addr: 0x%x\n",
		 msg->flags & RPMSG_NS_DESTROY ? "Destroy" : "Create",
		 msg->name, msg->addr);

	struct rpmsg_channel_info chinfo;

	strncpy(chinfo.name, msg->name, sizeof(chinfo.name));
	chinfo.src = RPMSG_ADDR_ANY;
	chinfo.dst = msg->addr;

	if (msg->flags & RPMSG_NS_DESTROY) {
		int res = rpmsg_unregister_device(dev, &chinfo);
		if (res) {
			dev_err(dev, "rpmsg_unregister_device failed, err: %d\n", res);
            return res;
        }
	} else {
		struct rpmsg_device *rdev = lbrp_create_channel(lbrp, &chinfo);
		if (IS_ERR_OR_NULL(rdev)) {
			dev_err(dev, "lbrp_create_channel failed\n");
            return -EFAULT;
        }
	}

	return 0;
}

// Searches for the channel described by @chinfo among children
// of the @parent device.
//
// RETURNS:
//      true: channel exists
//      false: channel doesn't exist
bool lbrp_channel_exists(
            struct device *parent
            , struct rpmsg_channel_info *chinfo)
{
    struct device *tgt = rpmsg_find_device(parent, chinfo);
	if (tgt) {
		// find incs the refcount, we need to drop it
		put_device(tgt);
        return true;
	}

    return false;
}

// Called by the kernel to request destruction of the channel device.
// Say when its refcount goes 0.
static void lbrp_rpmsg_release_device(struct device *dev)
{
	struct rpmsg_device *rpdev = to_rpmsg_device(dev);
	struct lbrp_rpmsg_channel_dev *ch_dev = to_lbrp_rpmsg_channel_dev(rpdev);

	kfree(ch_dev);
}

// Creates the rpmsg service (local one) backed by lbrp device.
//
// NOTE: it eventually calls the rpmsg_register_device(...)
//      which leads to probing the target rpmsg service driver.
static struct rpmsg_device *lbrp_create_channel(
            struct lb_rpmsg_proc_dev *lbrp
            , struct rpmsg_channel_info *chinfo)
{
	if (lbrp_channel_exists(lbrp, chinfo)) {
		dev_err(lbrp, "channel %s:%x:%x already exists\n",
				chinfo->name, chinfo->src, chinfo->dst);
		return NULL;
	}

	struct lbrp_rpmsg_channel_dev *new_ch;
    new_ch = kzalloc(sizeof(*new_ch), GFP_KERNEL);
	if (!new_ch) {
        dev_err(lbrp, "channel dev malloc failed.");
		return NULL;
    }

	struct rpmsg_device *rpdev = &new_ch->rpdev;

	rpdev->src = chinfo->src;
	rpdev->dst = chinfo->dst;
	rpdev->ops = &lbrp_rpmsg_ops;
	// if rpmsg server channels has predefined local address
	// their existence needs to be announced remotely
	rpdev->announce = (rpdev->src != RPMSG_ADDR_ANY);
	strncpy(rpdev->id.name, chinfo->name, RPMSG_NAME_SIZE);
	rpdev->dev.parent = lbrp->dev;
	rpdev->dev.release = lbrp_rpmsg_release_device;

	int res = rpmsg_register_device(rpdev);
	if (res) {
        free(new_ch);
        dev_err(lbrp, "Failed to register new lbrp channel.");
		return NULL;
    }

	return rpdev;
}

// Pops the announcement from the announcement queue. If queue is empty
// returns NULL.
//
// RETURNS:
//      !NULL: the first announcement
struct rpmsg_announcement_entry *entry __lbrp_remote_announcement_pop(
	        struct lb_rpmsg_proc_dev *lbrp)
{
    mutex_lock(&lbrp->rpmsg_announcements_lock);
    struct rpmsg_announcement_entry *entry
                = list_first_entry_or_null(&lbrp->rpmsg_announcements
                                           , struct rpmsg_announcement_entry
                                           , list_anchor);
    if (!IS_ERR_OR_NULL(entry)) {
        list_del(&entry->list_anchor);
    }

    mutex_unlock(&lbrp->rpmsg_announcements_lock);

    return entry;
}

// destroys the remote announcement.
// NOTE: the announcement must be already removed from the list
void __lbrp_remote_announcement_destroy(struct rpmsg_announcement_entry *entry)
{
    free(entry);
}

// Provides the lbrp rpmsg announcementes to the userland. Is called whenever
// userland reads the announcements file from sysfs.
// It provides one announcement on each read.
//
// @dev {valid ptr} the pointer to the device, which is bound to our
//      lb_rpmsg_proc_dev device.
// @attr {valid ptr} device attribute properties
// @buf {valid ptr} buffer to write output to userspace
//
// RETURNS:
//        0: No data
//      > 0: size of data to be showed in userspace
static ssize_t announcements_show(
		struct device *dev, struct device_attribute *attr, char *buf)
{
	struct lb_rpmsg_proc_dev *lbrp
                = (struct lb_rpmsg_proc_dev *)dev_get_drvdata(dev);

    struct rpmsg_announcement_entry *entry
            = __lbrp_remote_announcement_pop(lbrp);

    if (IS_ERR_OR_NULL(entry)) {
        return 0;
    }

    ssize_t length = scnprintf(buf, PAGE_SIZE, "%s:%d:%s"
                               , entry->msg, entry->addr
                               , flags & RPMSG_NS_DESTROY ? "d" : "c");

    __lbrp_remote_announcement_destroy(entry);

	return length;
}
static DEVICE_ATTR_RO(announcements);

// Tells the other side that we just created a new channel and it is
// avileable for communication.
// @flags RPMSG_NS_CREATE or RPMSG_NS_DESTROY
static int lbrp_rpmsg_announce(struct rpmsg_device *rpdev, uint32_t flags)
{
	struct lb_rpmsg_proc_dev *lbrp = rpdev->dev.parent;
	struct device *dev = lbrp->dev;

	if (rpdev->announce && rpdev->ept) {
        struct rpmsg_announcement_entry *entry
	            = kzalloc(sizeof(struct rpmsg_announcement_entry), GFP_KERNEL);

        if (IS_ERR_OR_NULL(entry)) {
            return -ENOMEM;
        }

        INIT_LIST_HEAD(&entry->list_anchor);

		strncpy(entry->msg.name, rpdev->id.name, RPMSG_NAME_SIZE);
		entry->msg.addr = rpdev->ept->addr;
		entry->msg.flags = flags;

        mutex_lock(&lbrp->rpmsg_announcements_lock);

        list_add_tail(&entry->list_anchor, &lbrp->rpmsg_announcements->list_anchor);

        mutex_unlock(&lbrp->rpmsg_announcements_lock);
	}

	return 0;
}

// Tells the other side that we just created a new channel and it is
// avileable for communication. Called automatically by the rpmsg core.
static int lbrp_rpmsg_announce_create(struct rpmsg_device *rpdev)
{
	return lbrp_rpmsg_announce(rpdev, RPMSG_NS_CREATE);
}

// Tells the other side that we are about to delete the channel and it
// will not be available for communication anymore.
// Called automatically by the rpmsg core.
static int lbrp_rpmsg_announce_destroy(struct rpmsg_device *rpdev)
{
	return lbrp_rpmsg_announce(rpdev, RPMSG_NS_DESTROY);
}

//----------------------------- ORG SECTION ---------------------------------//

// create the instance of the driver for the device.
static int lbrp_probe(struct device *dev)
{
    struct lb_rpmsg_proc_dev *lbrp = NULL;
    lbrp = kzalloc(sizeof(*lbrp), GFP_KERNEL);

    if (IS_ERR_OR_NULL(lbrp)) {
        return -ENOMEM;
    }

    lbrp->dev = dev;
	dev_set_drvdata(dev, lbrp);

	idr_init(&lbrp->endpoints);
	mutex_init(&lbrp->endpoints_lock);
    INIT_LIST_HEAD(&lbrp->rpmsg_announcements);
	mutex_init(&lbrp->rpmsg_announcements_lock);
    INIT_LIST_HEAD(&lbrp->remote_services);
	mutex_init(&lbrp->remote_services_lock);

	dev_info(lbrp->dev, "loopback rpmsg host is online\n");

	return 0;
}

// Removes a single local rpmsg device (one which was created by
// new channel announcement from the other side).
static int lbrp_remove_rpmsg_device(struct device *dev, void *data)
{
	device_unregister(dev);

	return 0;
}

// Removes all rpmsg devices and the main lbrp device.
static void lbrp_remove(struct device *dev)
{
    struct lb_rpmsg_proc_dev *lbrp = dev_get_drvdata(dev, lbrp);

    // Remote section
    
    // remove all remote endpoints first
    // NOTE: this will automatically remove all remote services as well
    //      and all local services which were created to match them.
    mutex_lock(&service->epts_lock);
    struct __lbrp_remote_ept *ept = NULL;
    while (ept = list_first_entry_or_null(&service->epts_head)) {
        __lbrp_remove_remote_ept(service, ept->addr);
    }
    mutex_unlock(&service->epts_lock);

    // remove all pending announcements
    struct rpmsg_announcement_entry *entry
    while (entry = __lbrp_remote_announcement_pop(lbrp)) {
        __lbrp_remote_announcement_destroy(entry);
    }

    // Local section

    // We need to destroy all local rpmsg channel devices which are still
    // there (were not created/related to the remote services)
	int ret = device_for_each_child(dev, NULL, lbrp_remove_rpmsg_device);
	if (ret) {
		dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);
    }

	idr_destroy(&lbrp->endpoints);

    // Members section

	mutex_destroy(&lbrp->endpoints_lock);
	mutex_destroy(&lbrp->rpmsg_announcements_lock);
	mutex_destroy(&lbrp->remote_services_lock);

	dev_set_drvdata(dev, NULL);

	dev_info(lbrp->dev, "loopback rpmsg host is closed\n");

	kfree(lbrp);
}

// List containing default attributes of lbrp device.
//
// @dev_attr_announcements exposes the announcements of the services
//      created on the local end.
// @dev_attr_create_ept creates the "remote" endpoint which will be
//      accociated with the local file.
// @dev_attr_remove_ept removes the "remote" endpoint which is
//      accociated with the local file.
static struct attribute *lbrp_dev_attrs[] = {
	&dev_attr_announcements.attr,
	&dev_attr_create_ept.attr,
	&dev_attr_remove_ept.attr,
	NULL,
};
ATTRIBUTE_GROUPS(lbrp_dev);

// The Lbrp driver compatible definition for
// matching the driver to devices available
//
// @compatible name of compatible driver
struct of_device_id lbrp_driver_id[] = {
	{
		.compatible = "loopback_rpmsg",
	}
};

// The Lbrp driver definition
//
// @probe probe device function
// @remove remove device function
// @driver structure driver definition
// @driver::owner the module owner
// @driver::name name of driver
// @driver::of_match_table compatible driver devices
// @driver::dev_groups devices groups with all attributes
struct platform_driver lbrp_driver = {
	.probe = lbrp_probe,
	.remove = lbrp_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "lbrp",
		.of_match_table = lbrp_driver_id,
		.dev_groups = lbrp_dev_groups
	}
};

// No need to overinvent here, we just create the lbrp device
// on init, and remove it on exit.
static int __init lbrp_init(void)
{
	struct platform_device * new_pdev = 
		    platform_device_register_simple(LBRP_DEV_NAME, 1, NULL, 0);

	if (IS_ERR_OR_NULL(new_pdev)) {
		pr_err("Could not register the lbrp device.");
		return -EFAULT;
	}

	return 0;
}
module_init(lbrp_init);

static void __exit lbrp_exit(void)
{
	struct device *lbrp_dev = 
		bus_find_device_by_name(&platform_bus_type, NULL, LBRP_DEV_NAME);

	if (IS_ERR_OR_NULL(lbrp_dev)) {
		pr_err("Lbrp device is null: something got broken.");
		return;
	}

	platform_device_unregister(to_platform_device(lbrp_device));
}
module_exit(lbrp_exit);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Rpmsg loopback processor for testing rpmsg device driver.");
MODULE_LICENSE("GPL v2");

