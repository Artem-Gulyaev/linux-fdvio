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

/* The feature bitmap for virtio rpmsg */
#define VIRTIO_RPMSG_F_NS	0 /* RP supports name service notifications */

/**
 * struct rpmsg_hdr - common header for all rpmsg messages
 * @src: source address
 * @dst: destination address
 * @reserved: reserved for future use
 * @len: length of payload (in bytes)
 * @flags: message flags
 * @data: @len bytes of message payload data
 *
 * Every message sent(/received) on the rpmsg bus begins with this header.
 */
struct rpmsg_hdr {
	u32 src;
	u32 dst;
	u32 reserved;
	u16 len;
	u16 flags;
	u8 data[0];
} __packed;

/**
 * enum rpmsg_ns_flags - dynamic name service announcement flags
 *
 * @RPMSG_NS_CREATE: a new remote service was just created
 * @RPMSG_NS_DESTROY: a known remote service was just destroyed
 */
enum rpmsg_ns_flags {
	RPMSG_NS_CREATE		= 0,
	RPMSG_NS_DESTROY	= 1,
};

/*
 * We're allocating buffers of 512 bytes each for communications. The
 * number of buffers will be computed from the number of buffers supported
 * by the vring, upto a maximum of 512 buffers (256 in each direction).
 *
 * Each buffer will have 16 bytes for the msg header and 496 bytes for
 * the payload.
 *
 * This will utilize a maximum total space of 256KB for the buffers.
 *
 * We might also want to add support for user-provided buffers in time.
 * This will allow bigger buffer size flexibility, and can also be used
 * to achieve zero-copy messaging.
 *
 * Note that these numbers are purely a decision of this driver - we
 * can change this without changing anything in the firmware of the remote
 * processor.
 */
#define MAX_RPMSG_NUM_BUFS	(512)
#define MAX_RPMSG_BUF_SIZE	(512)

/*
 * Local addresses are dynamically allocated on-demand.
 * We do not dynamically assign addresses from the low 1024 range,
 * in order to reserve that address range for predefined services.
 */
#define RPMSG_RESERVED_ADDRESSES	(1024)

/* Address 53 is reserved for advertising remote services */
#define RPMSG_NS_ADDR			(53)

static void virtio_rpmsg_destroy_ept(struct rpmsg_endpoint *ept);
static int virtio_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len);
static int virtio_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			       u32 dst);
static int virtio_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
					u32 dst, void *data, int len);
static int virtio_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len);
static int virtio_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				  int len, u32 dst);
static int virtio_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					   u32 dst, void *data, int len);

/**
 * rpmsg_send_offchannel_raw() - send a message across to the remote processor
 * @rpdev: the rpmsg channel
 * @src: source address
 * @dst: destination address
 * @data: payload of message
 * @len: length of payload
 * @wait: indicates whether caller should block in case no TX buffers available
 *
 * This function is the base implementation for all of the rpmsg sending API.
 *
 * It will send @data of length @len to @dst, and say it's from @src. The
 * message will be sent to the remote processor which the @rpdev channel
 * belongs to.
 *
 * The message is sent using one of the TX buffers that are available for
 * communication with this remote processor.
 *
 * If @wait is true, the caller will be blocked until either a TX buffer is
 * available, or 15 seconds elapses (we don't want callers to
 * sleep indefinitely due to misbehaving remote processors), and in that
 * case -ERESTARTSYS is returned. The number '15' itself was picked
 * arbitrarily; there's little point in asking drivers to provide a timeout
 * value themselves.
 *
 * Otherwise, if @wait is false, and there are no TX buffers available,
 * the function will immediately fail, and -ENOMEM will be returned.
 *
 * Normally drivers shouldn't use this function directly; instead, drivers
 * should use the appropriate rpmsg_{try}send{to, _offchannel} API
 * (see include/linux/rpmsg.h).
 *
 * Returns 0 on success and an appropriate error value on failure.
 */
static int rpmsg_send_offchannel_raw(struct rpmsg_device *rpdev,
				     u32 src, u32 dst,
				     void *data, int len, bool wait)
{
	struct lbrp_rpmsg_channel_dev *vch = to_lbrp_rpmsg_channel_dev(rpdev);
	struct virtproc_info *vrp = vch->vrp;
	struct device *dev = &rpdev->dev;
	struct scatterlist sg;
	struct rpmsg_hdr *msg;
	int err;

	/* bcasting isn't allowed */
	if (src == RPMSG_ADDR_ANY || dst == RPMSG_ADDR_ANY) {
		dev_err(dev, "invalid addr (src 0x%x, dst 0x%x)\n", src, dst);
		return -EINVAL;
	}

	/*
	 * We currently use fixed-sized buffers, and therefore the payload
	 * length is limited.
	 *
	 * One of the possible improvements here is either to support
	 * user-provided buffers (and then we can also support zero-copy
	 * messaging), or to improve the buffer allocator, to support
	 * variable-length buffer sizes.
	 */
	if (len > vrp->buf_size - sizeof(struct rpmsg_hdr)) {
		dev_err(dev, "message is too big (%d)\n", len);
		return -EMSGSIZE;
	}

	/* grab a buffer */
	msg = get_a_tx_buf(vrp);
	if (!msg && !wait)
		return -ENOMEM;

	/* no free buffer ? wait for one (but bail after 15 seconds) */
	while (!msg) {
		/* enable "tx-complete" interrupts, if not already enabled */
		rpmsg_upref_sleepers(vrp);

		/*
		 * sleep until a free buffer is available or 15 secs elapse.
		 * the timeout period is not configurable because there's
		 * little point in asking drivers to specify that.
		 * if later this happens to be required, it'd be easy to add.
		 */
		err = wait_event_interruptible_timeout(vrp->sendq,
					(msg = get_a_tx_buf(vrp)),
					msecs_to_jiffies(15000));

		/* disable "tx-complete" interrupts if we're the last sleeper */
		rpmsg_downref_sleepers(vrp);

		/* timeout ? */
		if (!err) {
			dev_err(dev, "timeout waiting for a tx buffer\n");
			return -ERESTARTSYS;
		}
	}

	msg->len = len;
	msg->flags = 0;
	msg->src = src;
	msg->dst = dst;
	msg->reserved = 0;
	memcpy(msg->data, data, len);

	dev_dbg(dev, "TX From 0x%x, To 0x%x, Len %d, Flags %d, Reserved %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);
#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("rpmsg_virtio TX: ", DUMP_PREFIX_NONE, 16, 1,
			 msg, sizeof(*msg) + msg->len, true);
#endif

	rpmsg_sg_init(&sg, msg, sizeof(*msg) + len);

	mutex_lock(&vrp->tx_lock);

	/* add message to the remote processor's virtqueue */
	err = virtqueue_add_outbuf(vrp->svq, &sg, 1, msg, GFP_KERNEL);
	if (err) {
		/*
		 * need to reclaim the buffer here, otherwise it's lost
		 * (memory won't leak, but rpmsg won't use it again for TX).
		 * this will wait for a buffer management overhaul.
		 */
		dev_err(dev, "virtqueue_add_outbuf failed: %d\n", err);
		goto out;
	}

	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(vrp->svq);
out:
	mutex_unlock(&vrp->tx_lock);
	return err;
}

static int virtio_rpmsg_send(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int virtio_rpmsg_sendto(struct rpmsg_endpoint *ept, void *data, int len,
			       u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int virtio_rpmsg_send_offchannel(struct rpmsg_endpoint *ept, u32 src,
					u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, true);
}

static int virtio_rpmsg_trysend(struct rpmsg_endpoint *ept, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr, dst = rpdev->dst;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int virtio_rpmsg_trysendto(struct rpmsg_endpoint *ept, void *data,
				  int len, u32 dst)
{
	struct rpmsg_device *rpdev = ept->rpdev;
	u32 src = ept->addr;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int virtio_rpmsg_trysend_offchannel(struct rpmsg_endpoint *ept, u32 src,
					   u32 dst, void *data, int len)
{
	struct rpmsg_device *rpdev = ept->rpdev;

	return rpmsg_send_offchannel_raw(rpdev, src, dst, data, len, false);
}

static int rpmsg_recv_single(struct virtproc_info *vrp, struct device *dev,
			     struct rpmsg_hdr *msg, unsigned int len)
{
	struct rpmsg_endpoint *ept;
	struct scatterlist sg;
	int err;

	dev_dbg(dev, "From: 0x%x, To: 0x%x, Len: %d, Flags: %d, Reserved: %d\n",
		msg->src, msg->dst, msg->len, msg->flags, msg->reserved);
#if defined(CONFIG_DYNAMIC_DEBUG)
	dynamic_hex_dump("rpmsg_virtio RX: ", DUMP_PREFIX_NONE, 16, 1,
			 msg, sizeof(*msg) + msg->len, true);
#endif

	/*
	 * We currently use fixed-sized buffers, so trivially sanitize
	 * the reported payload length.
	 */
	if (len > vrp->buf_size ||
	    msg->len > (len - sizeof(struct rpmsg_hdr))) {
		dev_warn(dev, "inbound msg too big: (%d, %d)\n", len, msg->len);
		return -EINVAL;
	}

	/* use the dst addr to fetch the callback of the appropriate user */
	mutex_lock(&vrp->endpoints_lock);

	ept = idr_find(&vrp->endpoints, msg->dst);

	/* let's make sure no one deallocates ept while we use it */
	if (ept)
		kref_get(&ept->refcount);

	mutex_unlock(&vrp->endpoints_lock);

	if (ept) {
		/* make sure ept->cb doesn't go away while we use it */
		mutex_lock(&ept->cb_lock);

		if (ept->cb)
			ept->cb(ept->rpdev, msg->data, msg->len, ept->priv,
				msg->src);

		mutex_unlock(&ept->cb_lock);

		/* farewell, ept, we don't need you anymore */
		kref_put(&ept->refcount, __ept_on_refcount0);
	} else
		dev_warn(dev, "msg received with no recipient\n");

	/* publish the real size of the buffer */
	rpmsg_sg_init(&sg, msg, vrp->buf_size);

	/* add the buffer back to the remote processor's virtqueue */
	err = virtqueue_add_inbuf(vrp->rvq, &sg, 1, msg, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	return 0;
}








static int rpmsg_probe(struct virtio_device *vdev)
{
	vq_callback_t *vq_cbs[] = { rpmsg_recv_done, rpmsg_xmit_done };
	static const char * const names[] = { "input", "output" };
	struct virtqueue *vqs[2];
	struct virtproc_info *vrp;
	void *bufs_va;
	int err = 0, i;
	size_t total_buf_space;
	bool notify;

	vrp = kzalloc(sizeof(*vrp), GFP_KERNEL);
	if (!vrp)
		return -ENOMEM;

	vrp->vdev = vdev;

	idr_init(&vrp->endpoints);
	mutex_init(&vrp->endpoints_lock);
	mutex_init(&vrp->tx_lock);
	init_waitqueue_head(&vrp->sendq);

	/* We expect two virtqueues, rx and tx (and in this order) */
	err = virtio_find_vqs(vdev, 2, vqs, vq_cbs, names, NULL);
	if (err)
		goto free_vrp;

	vrp->rvq = vqs[0];
	vrp->svq = vqs[1];

	/* we expect symmetric tx/rx vrings */
	WARN_ON(virtqueue_get_vring_size(vrp->rvq) !=
		virtqueue_get_vring_size(vrp->svq));

	/* we need less buffers if vrings are small */
	if (virtqueue_get_vring_size(vrp->rvq) < MAX_RPMSG_NUM_BUFS / 2)
		vrp->num_bufs = virtqueue_get_vring_size(vrp->rvq) * 2;
	else
		vrp->num_bufs = MAX_RPMSG_NUM_BUFS;

	vrp->buf_size = MAX_RPMSG_BUF_SIZE;

	total_buf_space = vrp->num_bufs * vrp->buf_size;

	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(vdev->dev.parent,
				     total_buf_space, &vrp->bufs_dma,
				     GFP_KERNEL);
	if (!bufs_va) {
		err = -ENOMEM;
		goto vqs_del;
	}

	dev_dbg(&vdev->dev, "buffers: va %pK, dma %pad\n",
		bufs_va, &vrp->bufs_dma);

	/* half of the buffers is dedicated for RX */
	vrp->rbufs = bufs_va;

	/* and half is dedicated for TX */
	vrp->sbufs = bufs_va + total_buf_space / 2;

	/* set up the receive buffers */
	for (i = 0; i < vrp->num_bufs / 2; i++) {
		struct scatterlist sg;
		void *cpu_addr = vrp->rbufs + i * vrp->buf_size;

		rpmsg_sg_init(&sg, cpu_addr, vrp->buf_size);

		err = virtqueue_add_inbuf(vrp->rvq, &sg, 1, cpu_addr,
					  GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}

	/* suppress "tx-complete" interrupts */
	virtqueue_disable_cb(vrp->svq);

	vdev->priv = vrp;

	/* if supported by the remote processor, enable the name service */
	if (virtio_has_feature(vdev, VIRTIO_RPMSG_F_NS)) {
		/* a dedicated endpoint handles the name service msgs */
		vrp->ns_ept = __lbrp_rpmsg_create_ept(vrp, NULL, rpmsg_ns_cb,
						vrp, RPMSG_NS_ADDR);
		if (!vrp->ns_ept) {
			dev_err(&vdev->dev, "failed to create the ns ept\n");
			err = -ENOMEM;
			goto free_coherent;
		}
	}

	/*
	 * Prepare to kick but don't notify yet - we can't do this before
	 * device is ready.
	 */
	notify = virtqueue_kick_prepare(vrp->rvq);

	/* From this point on, we can notify and get callbacks. */
	virtio_device_ready(vdev);

	/* tell the remote processor it can start sending messages */
	/*
	 * this might be concurrent with callbacks, but we are only
	 * doing notify, not a full kick here, so that's ok.
	 */
	if (notify)
		virtqueue_notify(vrp->rvq);

	dev_info(&vdev->dev, "rpmsg host is online\n");

	return 0;

free_coherent:
	dma_free_coherent(vdev->dev.parent, total_buf_space,
			  bufs_va, vrp->bufs_dma);
vqs_del:
	vdev->config->del_vqs(vrp->vdev);
free_vrp:
	kfree(vrp);
	return err;
}

/**
 * struct virtproc_info - virtual remote processor state
 * @vdev:	the virtio device
 * @rvq:	rx virtqueue
 * @svq:	tx virtqueue
 * @rbufs:	kernel address of rx buffers
 * @sbufs:	kernel address of tx buffers
 * @num_bufs:	total number of buffers for rx and tx
 * @buf_size:   size of one rx or tx buffer
 * @last_sbuf:	index of last tx buffer used
 * @bufs_dma:	dma base addr of the buffers
 * @tx_lock:	protects svq, sbufs and sleepers, to allow concurrent senders.
 *		sending a message might require waking up a dozing remote
 *		processor, which involves sleeping, hence the mutex.
 * @sendq:	wait queue of sending contexts waiting for a tx buffers
 * @sleepers:	number of senders that are waiting for a tx buffer
 * @ns_ept:	the bus's name service endpoint
 *
 * This structure stores the rpmsg state of a given virtio remote processor
 * device (there might be several virtio proc devices for each physical
 * remote processor).
 */
struct virtproc_info {
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq;
	void *rbufs, *sbufs;
	unsigned int num_bufs;
	unsigned int buf_size;
	int last_sbuf;
	dma_addr_t bufs_dma;
	struct mutex tx_lock;
	wait_queue_head_t sendq;
	atomic_t sleepers;
	struct rpmsg_endpoint *ns_ept;
};



////////////////////--------------------////////////////////    VERIFIED BEGIN

#define to_lbrp_rpmsg_channel_dev(_lbrp_ch_dev_ptr) \
	container_of(_lbrp_ch_dev_ptr, struct lbrp_rpmsg_channel_dev, rpdev)


#define LBRP_MAX_EPT_FILE_NAME_SIZE 20

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

////////////////////--------------------////////////////////    VERIFIED END

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
struct __lbrp_remote_ept {
    uint32_t addr;
	struct list_head list_anchor;
	struct list_head rx_msgs_head;
	struct mutex rx_msgs_lock;
    struct attribute sysfs_attr;
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

////////////////////--------------------////////////////////    VERIFIED BEGIN
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


// defines the remote service object type
static const struct kobj_type remote_service_object_type {
        .release = __lbrp_release_remote_service_on_refcount0
        , .sysfs_ops = &kobj_sysfs_ops,
};


static const struct rpmsg_device_ops lbrp_rpmsg_ops = {
	.create_ept = lbrp_rpmsg_create_ept,
	.announce_create = lbrp_rpmsg_announce_create,
	.announce_destroy = lbrp_rpmsg_announce_destroy,
};

static const struct rpmsg_endpoint_ops lbrp_endpoint_ops = {
	.destroy_ept = virtio_rpmsg_destroy_ept,
////////////////////--------------------////////////////////    VERIFIED END
	.send = virtio_rpmsg_send,
	.sendto = virtio_rpmsg_sendto,
	.send_offchannel = virtio_rpmsg_send_offchannel,
	.trysend = virtio_rpmsg_trysend,
	.trysendto = virtio_rpmsg_trysendto,
	.trysend_offchannel = virtio_rpmsg_trysend_offchannel,
};

////////////////////--------------------////////////////////    VERIFIED BEGIN
// Rpmsg on refcount->0 destructor.
// @kref: the ept's reference count
// Called automatically when refcount of ept reaches 0.
static void __ept_on_refcount0(struct kref *kref)
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
	kref_put(&ept->refcount, __ept_on_refcount0);
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

	kref_put(&ept->refcount, __ept_on_refcount0);
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

// The sysfs create_ept_store function get's triggered whenever from
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

    uint32_t remote_addr;
    if (kstrtou32(addr_str, 0, &remote_addr)) {
        goto wrong_usage;
    }

    struct lb_rpmsg_proc_dev *lbrp
	        = (struct b_rpmsg_proc_dev *)dev_get_drvdata(dev);
    if (IS_ERR_OR_NULL(lbrp)) {
        dev_err(dev, "Sorry, no lbrp dev referenced by the dev.");
        goto done;
    }

    struct __lbrp_remote_service *rservice = __lbrp_create_remote_service(
                                                               lbrp, name);

    if (IS_ERR_OR_NULL(rservice)) {
        goto done;
    }
////////////////////--------------------////////////////////    VERIFIED END








    kobject_init(struct kobject *kobj, struct kobj_type *ktype);





		if (!IS_ERR_OR_NULL(sysfs_get_dirent(dev->kobj.sd, "transport_RW"))) {
			fd_tt_err("Files already exist");
			return -EINVAL;
		}

		if (device_create_file(dev, &dev_attr_transport_RW) != 0) {
			fd_tt_err("Error creating the transport_RW file.");
			return -EINVAL;
		}

	return count;

wrong_usage:
	dev_err(dev,
            "WRITE FORMAT:  \"your-service-name ADDR\""
            " * your-service-name - a string with no spaces"
            " * single space"
            " * ADDR - the int32_t the address of the remote endpoint");
done:
	return -EINVAL;
}
static DEVICE_ATTR_WO(create_ept);

////////////////////--------------------////////////////////    VERIFIED BEGIN

// Creates/gets an endpoint with given own address for the given service.
// NOTE: if endpoint already exists is is not an error.
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

    struct lb_rpmsg_proc_dev * lbrp = __lbrp_from_service(service);

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

    mutex_lock(&service->epts_lock);
    list_add_tail(&ept->list_anchor, &service->epts_head);
    mutex_unlock(&service->epts_lock);

    int res = sysfs_create_file(service->kobj, &ept->sysfs_attr);
    if (res != 0) {
        dev_err(lbrp->dev, "failed to create ept attr: %s", ept->sysfs_attr.name);
        goto sysfs_create_failed;
    }

    return ept;

sysfs_create_failed:
    mutex_lock(&service->epts_lock);
    list_del(&ept->list_anchor);
    mutex_unlock(&service->epts_lock);

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
void __lbrp_remove_remote_ept(
            struct __lbrp_remote_service *service
            , uint32_t own_address)
{
    struct lb_rpmsg_proc_dev * lbrp = __lbrp_from_service(service);

    dev_info(lbrp->dev, "removing ept %d of %s service"
             , own_address, service->name);

    // drop it from the service list, so no incoming messages
    // will be appended to the ept messages

    mutex_lock(&service->epts_lock);

    struct __lbrp_remote_ept *ept = NULL;
    list_for_each_entry(ept, &service->epts_head, list_anchor) {
        if (ept->addr == own_address) {
            break;
        }
    }
    if (list_entry_is_head(ept, &service->epts_head, list_anchor)) {
        mutex_unlock(&service->epts_lock);
        dev_warn("ept %d of %s service already doesn't exist"
                 , own_address, service->name);
        return;    
    }

    list_del(&ept->list_anchor);

    mutex_unlock(&service->epts_lock);

    // now we will remove the corresponding sysfs file
    sysfs_remove_file(&service->kobj, &ept->sysfs_attr);

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
}

// Adds the rx message to the list of RX messages (pending to be read
// by userland from sysfs) of the remote endpoint.
//
// RETURNS:
//      NULL: didn't make it
//      else: valid pointer to newly added msg
struct __lbrp_remote_ept_msg __lbrp_remote_ept_push_rx_msg(
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

data_alloc_f:
    free(msg);
struct_alloc_f:
    return NULL;
}

// Pops the first pending message out of the RX pending queue (toward the
// sysfs). It removes it from pending list, but doesn't destroy.
struct __lbrp_remote_ept_msg *__lbrp_remote_ept_pop_rx_msg(
        struct __lbrp_remote_ept *ept)
{
    mutex_lock(&ept->rx_msgs_lock);

    struct __lbrp_remote_ept_msg *msg
                = list_first_entry_or_null(&ept->rx_msgs_head
                                           , struct __lbrp_remote_ept_msg
                                           , list_anchor);
    list_del(&msg->list_anchor);

    mutex_unlock(&ept->rx_msgs_lock);

    return msg;
}

// Actually destroys the remote rx message.
// NOTE: the message must be already removed from any lists already.
void __lbrp_remote_ept_destroy_rx_msg(
    struct __lbrp_remote_ept_msg *msg)
{
    if (IS_ERR_OR_NULL(msg)) {
        return;
    }

    msg->data_len_bytes = 0;
    free(msg->data);
    free(msg);
}

// Creates the remote service record for the lbrp. If service
// already exists - all fine, no error. New service has no own endpoints.
// @lbrp our device.
// @name the remote service name to create.
//
// LOCKING: does all locking itself.
//
// RETURNS:
//      the ptr to existing or newly created remote service: if all fine
//      NULL: if something went wrong
struct __lbrp_remote_service *__lbrp_create_remote_service(
            struct lb_rpmsg_proc_dev *lbrp
            , char *name)
{
    dev_info(lbrp->dev, "Creating remote service: %s", name);

    mutex_lock(&lbrp->remote_services_lock);
    // check if service is there already
    struct __lbrp_remote_service *rservice = NULL;
    list_for_each_entry(rservice, &lbrp->remote_services, list_anchor) {
        if (strncmp(name, rservice->name, sizeof(rservice->name)) == 0) {
            goto done:
        }
    }

    // need to create a new one
    rservice = kzalloc(sizeof(*rservice), GFP_KERNEL);
    if (IS_ERR_OR_NULL(rservice)) {
        dev_err(lbrp->dev, "no memory for new remote service");
        goto malloc_failed;
    }

    strncpy(&rservice.name[0], name, sizeof(rservice.name));
    if (rservice.name[sizeof(rservice.name) - 1] != 0) {
        dev_err(lbrp->dev, "name is too big, must fit into %d chars"
                , sizeof(rservice.name));
        goto name_cpy_failed;
    }

    mutex_init(&rservice->epts_lock);
    INIT_LIST_HEAD(&rservice->epts_head);
    INIT_LIST_HEAD(&rservice->list_anchor);

    kobject_init(&rservice->kobj, &remote_service_object_type);

    list_add_tail(&rservice->list_anchor, &lbrp->remote_services);

    int res = kobject_add(&rservice->kobj, &lbrp->dev->kobj, "%s", name);
    if (res != 0) {
        dev_err(lbrp->dev, "failed to add remote service, err: %d", res);
        list_del(&rservice->list_anchor);
        kobject_put(&rservice->kobj);
        rservice = NULL;
        goto kobj_add_failed;
    }

done:
    mutex_unlock(&lbrp->remote_services_lock);
    return rservice;

name_cpy_failed:
    free(rservice);
malloc_failed:
kobj_add_failed:
    mutex_unlock(&lbrp->remote_services_lock);
    return rservice;
}

// RETURNS: the lbrp device for given service
struct lb_rpmsg_proc_dev * __lbrp_from_service(struct __lbrp_remote_service *rs)
{
    struct device *lbrp_dev = container_of(rs->kobj->parent, struct device, kobj);
    return (struct lb_rpmsg_proc_dev *)dev_get_drvdata(lbrp_dev);
}

// Releases the remote service. Called by refcounter framework when refcount 
// of the remote service reaches 0. Don't call directly.
void __lbrp_release_remote_service_on_refcount0(struct kobject *kobject)
{
    struct __lbrp_remote_service *rservice
        = container_of(kobject, struct __lbrp_remote_service, kobj);

    struct lb_rpmsg_proc_dev *lbrp = __lbrp_from_service(rservice);

    dev_info(lbrp->dev, "removed remote service: %s", rservice.name);

    free(rservice);
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
//
// @lbrp our device to work with
// @msg service (channel) announcement info
//
// RETURNS:
//      0: all fine
//      <0: negated error code
static int lb_rpmsg_service_ctl(
            struct lb_rpmsg_proc_dev *lbrp
	        , struct rpmsg_ns_msg *msg
            , uint32_t local_addr)
{
	struct device *dev = lbrp->dev;

	dev_info(dev, "%sing lbrp channel \"%s\", addr: 0x%x\n",
		 msg->flags & RPMSG_NS_DESTROY ? "Destroy" : "Creat",
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

// Creates the rpmsg service backed by lbrp device.
// This channel has a "remote" endpoint in the local
// sysfs file, so local applications can test all data
// flows for rpmsg drivers.
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
	rpdev->dev.parent = lbrp;
	rpdev->dev.release = lbrp_rpmsg_release_device;

	int res = rpmsg_register_device(rpdev);
	if (res) {
        free(new_ch);
        dev_err(lbrp, "Failed to register new lbrp channel.");
		return NULL;
    }

	return rpdev;
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
	struct lb_rpmsg_proc_dev *lbrp = (struct lb_rpmsg_proc_dev *)dev_get_drvdata(dev);
    ssize_t length = 0;

    mutex_lock(&lbrp->rpmsg_announcements_lock);

	if (list_empty(&lbrp->rpmsg_announcements)) {
        goto done;
    }

    // we tell only one announcement per single read
    struct rpmsg_announcement_entry *entry = container_of(
                    lbrp->rpmsg_announcements.next
			        , struct rpmsg_announcement_entry
			        , list_anchor);
    

	length = scnprintf(buf, PAGE_SIZE, "%s:%d:%s"
                       , entry->msg, entry->addr
                       , flags & RPMSG_NS_DESTROY ? "d" : "c");

    list_del(&entry->list_anchor);
    free(entry);

done:
    mutex_unlock(&lbrp->rpmsg_announcements_lock);

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
// avileable for communication.
static int lbrp_rpmsg_announce_create(struct rpmsg_device *rpdev)
{
	return lbrp_rpmsg_announce(rpdev, RPMSG_NS_CREATE);
}


// Tells the other side that we are about to delete the channel and it
// will not be available for communication anymore.
static int lbrp_rpmsg_announce_destroy(struct rpmsg_device *rpdev)
{
	return lbrp_rpmsg_announce(rpdev, RPMSG_NS_DESTROY);
}

////////////////////--------------------////////////////////    VERIFIED END




























































static int rpmsg_remove_device(struct device *dev, void *data)
{
	device_unregister(dev);

	return 0;
}

static void rpmsg_remove(struct virtio_device *vdev)
{
	struct virtproc_info *vrp = vdev->priv;
	size_t total_buf_space = vrp->num_bufs * vrp->buf_size;
	int ret;

	vdev->config->reset(vdev);

	ret = device_for_each_child(&vdev->dev, NULL, rpmsg_remove_device);
	if (ret)
		dev_warn(&vdev->dev, "can't remove rpmsg device: %d\n", ret);

	if (vrp->ns_ept)
		__rpmsg_remove_ept(vrp, vrp->ns_ept);

	idr_destroy(&vrp->endpoints);

	vdev->config->del_vqs(vrp->vdev);

	dma_free_coherent(vdev->dev.parent, total_buf_space,
			  vrp->rbufs, vrp->bufs_dma);

	kfree(vrp);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_RPMSG, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_RPMSG_F_NS,
};

static struct virtio_driver virtio_ipc_driver = {
	.feature_table	= features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.id_table	= id_table,
	.probe		= rpmsg_probe,
	.remove		= rpmsg_remove,
};

static int __init rpmsg_init(void)
{
	int ret;

	ret = register_virtio_driver(&virtio_ipc_driver);
	if (ret)
		pr_err("failed to register virtio driver: %d\n", ret);

	return ret;
}
subsys_initcall(rpmsg_init);

static void __exit rpmsg_fini(void)
{
	unregister_virtio_driver(&virtio_ipc_driver);
}
module_exit(rpmsg_fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Rpmsg loopback processor for testing");
MODULE_LICENSE("GPL v2");
