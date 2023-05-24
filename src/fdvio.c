// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN
/*
 * This file provides a full-duplex symmetrical VirtIO device (Fdvio driver)
 * to execute symmetrical full-duplex communication on top of the rpmsg
 * transport.
 * The device exposes full_duplex_interface to the upper layers.
 * The device uses the rpmsg interface provided by rpmsg facilities below.
 *
 * Copyright (c) 2022 Robert Bosch GmbH
 * Artem Gulyaev <Artem.Gulyaev@de.bosch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SPDX-License-Identifier: GPL-2.0


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rpmsg.h>

#include <linux/full_duplex_interface.h>


/* --------------------- UTILITIES SECTION ----------------------------- */


#define FDVIO_LOG_PREFIX "fdvio: "


#define fdvio_emerg(fmt, ...)                                               \
    dev_emerg(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_crit(dev, fmt, ...)                                           \
    dev_crit(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_alert(dev, fmt, ...)                                          \
    dev_alert(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_err(dev, fmt, ...)                                            \
    dev_err(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_warn(dev, fmt, ...)                                           \
    dev_warn(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_notice(dev, fmt, ...)                                         \
    dev_notice(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_info(dev, fmt, ...)                                           \
    dev_info(fdvio->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)


#define CAST_DEVICE_TO_FDVIO                                        \
        struct fdvio_dev *fdvio = (struct fdvio_dev *fdvio)device;
#define FDVIO_CHECK_DEVICE(error_action)                    \
	if (IS_ERR_OR_NULL(fdvio)) {                            \
		fdvio_err("%s: no device;\n", __func__);            \
		error_action;                                       \
	}
#define FDVIO_CHECK_KERNEL_DEVICE(error_action)             \
	if (IS_ERR_OR_NULL(fdvio->dev)) {                       \
		fdvio_err("%s: no kernel device;\n", __func__);     \
		error_action;                                       \
	}
#define FDVIO_CHECK_PTR(ptr, error_action)                     \
	if (IS_ERR_OR_NULL(ptr)) {                                 \
		fdvio_err("%s: "#ptr"(%px): ptr error\n"               \
				, __func__, ptr);                              \
		error_action;                                          \
	}
#define FDVIO_ON_FINISH(action)                   \
	if (fdvio->finishing) {                       \
		action;                                   \
	}

#define FDVIO_SWITCH_STRICT(from, to)                          \
	(atomic_cmpxchg(&fdvio->state,                             \
					FDVIO_STATE_##to,                          \
					FDVIO_STATE_##from) != FDVIO_STATE_##to)
#define FDVIO_SWITCH_FORCED(to)                          \
	atomic_set(&fdvio->state, FDVIO_STATE_##to)

/* --------------------------- MAIN STRUCTURES --------------------------*/


// The workflow is symmetrical:
//
//      A -> B == B -> A
//
// Overall interaction scheme (symmetrical regarding the sides swap):
//
// * STATE: IDLE (NOOP) nothing happens, nobody waits for anything
// 
// * STATE: XFER consists of the data exchange and delivery of the
//      data to the upper layer.
//
// * STATE: ERROR is reached if any error condition is met, like
//      xfer data size mismatch between sized, or timeout waiting for other
//      xfer.
//
// Fdvio will be based on the rpmsg, which will use in the main case:
// https://github.com/renesas-rcar/linux-bsp/blob/rcar-5.1.4.rc3/saferendering.rc10/drivers/remoteproc/rcar_cr7_remoteproc.c
//
//
// NOTE: main documentation: https://docs.kernel.org/staging/rpmsg.html
// also:
//      * https://elixir.bootlin.com/linux/latest/source/include/linux/rpmsg.h#L55
//


// The cold-and-dark state of the driver - before initialization was even
// carried out.
#define FDVIO_STATE_COLD 0
// First state after COLD. We enter it right upon the initialization start.
#define FDVIO_STATE_INITIALIZING 1
// Last state before COLD. We enter it right upon the shut down start.
#define FDVIO_STATE_SHUTTING_DOWN 2
// State, when nothing is happening, no one waits for anything, no tranfers
// are executing, no timeouts active. We just sit and wait for an external
// kick from either side.
#define FDVIO_STATE_IDLE 3
// We come to this state when someone kicks us from the IDLE state normally.
// It can be:
// * Data-ready-to-read callback/event from the other side.
//   NOTE: this event comes from a callback registered by: rpmsg_create_ept(...)
// * Upper layer kicks us with data xfer request.
//   NOTE: this is done in data_xchange(...) function implementation AND
//      in the xfer_done/xfer_fail callbacks.
#define FDVIO_STATE_XFER 4
// This state indicates an error in fdvio operation. Normally we need to notify
// the other side about the error and get out of this state as soon as possible.
#define FDVIO_STATE_ERROR 5


// This value is used to identify if the instance of the driver data
// was already initialized once, and then the data fields there are expected
// to make sense. Otherwise we ignore the data fields on init, cause they
// are expected to be garbage.
//
// NOTE: this is not the absolute protection, but mostly the debugging aid.
#define FDVIO_MAGIC 0x83cad137

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END

// This data is located at the beginning of the Xfer data (prepended to xfer)
// which is "sent" to the other side. This data allows to identify
// the key xfer parameters and synchronize the fdvio drivers on
// both sides with each other.
//
// @xfer_size_bytes the size of the current xfer in bytes (size only of the
//      user data, the fdvio data is not included in this size).
// @fdvio_state the value to tell the other side any relevant information
//      like xfer sizes mismatch error indication, etc..
// @fdvio_error the specific error condition if the state is ERROR.
typedef struct {
    uint32_t xfer_size_bytes;
    uint32_t fdvio_state;
    uint32_t fdvio_error;
} fdvio_diagnostics_info;


// The device itself
// @magic the field where the FDVIO_MAGIC should be written upon the
//  initialization start.
// @state the current state of the device
// @dev the corresponding rpmsg device record in the kernel device facilities.
// @xfer the current xfer data - this data is also used for default xfer
//      data storage.
// @next_xfer_id stores the next xfer id - when xfer is just done, its
// 		value used to set the next xfer id, and then it gets incremented.
// @got_other_side_data within the XFER state is set to true only when
//      we have received the data from the other side
// @have_sent_our_data within the XFER state is set to true only when
//      we have sent our data to the other side
struct {
	uint32_t magic;
	struct rpmsg_device *dev;
	atomic_t state; 
	struct full_duplex_xfer *xfer;
	int next_xfer_id;

	bool got_other_side_data;
	bool have_sent_our_data;
} fdvio_dev;

/*---------------------- XFER IF COMMON METHODS ----------------------*/

// TODO: all methods of xfer reallocation can be moved to the
//      general xfer methods (at least consider this);


// Initializes the xfer data to the default empty state
// @xfer target xfer to reset.
void fdi_xfer_init(struct full_duplex_xfer *xfer)
{
	if (IS_ERR_OR_NULL(xfer)) {
		return;
	}
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Frees all data owned by @xfer and resets all xfer members.
//
// @xfer target xfer to free.
void fdi_xfer_free(struct full_duplex_xfer *xfer)
{
	if (IS_ERR_OR_NULL(xfer)) {
		return;
	}
	if (!IS_ERR_OR_NULL(xfer->data_tx)) {
		kfree(xfer->data_tx);
	}
	if (!IS_ERR_OR_NULL(xfer->data_rx_buf)) {
		kfree(xfer->data_rx_buf);
	}
	memset(xfer, 0, sizeof(struct full_duplex_xfer));
}

// Makes a deep copy the the xfer pointed by @src to the @dst location.
// Data is copied as well, so one ends up with two identical xfers in
// different locations.
// @src the pointer to the source xfer
// @dst the pointer to the destination xfer
//
// RETURNS:
//      0: upon success
//      <0: negated error code
int fdi_deep_xfer_copy(struct full_duplex_xfer *src
		, struct full_duplex_xfer *dst)
{
	if (IS_ERR_OR_NULL(src) || IS_ERR_OR_NULL(dst)) {
		return -EINVAL;
	}

	fdi_xfer_free(dst);

	dst->size_bytes = src->size_bytes;

	if (!IS_ERR_OR_NULL(src->data_tx) && src->size_bytes) {
		dst->data_tx = kmalloc(dst->size_bytes, GFP_KERNEL);
		if (!dst->data_tx) {
			goto tx_nomem;
		}
		memcpy(dst->data_tx, src->data_tx, dst->size_bytes);
	}

	if (!IS_ERR_OR_NULL(src->data_rx_buf) && src->size_bytes) {
		dst->data_rx_buf = kmalloc(dst->size_bytes, GFP_KERNEL);
		if (!dst->data_rx_buf) {
			goto rx_nomem;
		}
		memcpy(dst->data_rx_buf, src->data_rx_buf, dst->size_bytes);
	}

	dst->xfers_counter = src->xfers_counter;
	dst->id = src->id;
	dst->consumer_data = src->consumer_data;
	dst->done_callback = src->done_callback;
	return 0;

rx_nomem:
	kfree(dst->data_tx);
	dst->data_tx = NULL;
tx_nomem:
	dst->size_bytes = 0;
	return -ENOMEM;
}

// Allocates storages for RX or TX data for the xfer(of xfer->size_bytes size)
// if they were not allocated.
// @xfer the xfer to unfold
//
// RETURNS:
// 	     0: upon success
// 	     <0: negated error code
int fdi_xfer_unfold(struct full_duplex_xfer *xfer)
{
	if (IS_ERR_OR_NULL(xfer)) {
		return -EINVAL;
	}
	if (!xfer->size_bytes) {
		return 0;
	}
	if (IS_ERR_OR_NULL(xfer->data_tx)) {
		xfer->data_tx = kmalloc(xfer->size_bytes, GFP_KERNEL);
		if (!xfer->data_tx) {
			return -ENOMEM;
		}
	}
	if (IS_ERR_OR_NULL(xfer->data_rx_buf)) {
		xfer->data_rx_buf = kmalloc(xfer->size_bytes, GFP_KERNEL);
		if (!xfer->data_rx_buf) {
			return -ENOMEM;
		}
	}
	return 0;
}

/*---------------------- FDVIO DEVICE API ----------------------------*/

int fdvio_data_xchange(void __kernel *device
                    , struct __kernel full_duplex_xfer *xfer
                    , bool force_size_change)
{


}

int fdvio_default_data_update(void __kernel *device
                           , struct full_duplex_xfer *xfer
                           , bool force_size_change)
{
}

bool fdvio_is_running(void __kernel *device)
{
}

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN
// API
// Short: initializes the fdvio device and prepares it for work.
// For long description, see struct full_duplex_interface description.
//
// THREADING: on the same instance init can be called **only**
//    * if it is a brand newly created instance (no work was done on it yet),
//    * or if this instance was properly closed by fdvio_close(...) before.
__maybe_unused
int fdvio_init(void __kernel *device
		, struct full_duplex_xfer *default_xfer)
{
    CAST_DEVICE_TO_FDVIO;
    FDVIO_CHECK_DEVICE(return -ENODEV);
    FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);

    // if magic matches, we treat the the structue content as meaningful,
    // otherwise we treat the structure as completely uninitialized and
	// containing random garbage.
	//
	// NOTE: it is surely not a protection from an indended multithreading
	// 	initialization, only to catch some bugs mainly.
    if (fdvio->magic != FDVIO_MAGIC) {
		fdvio_info("starting initialization of device");
		fdvio->magic = FDVIO_MAGIC;
		FDVIO_SWITCH_FORCED(INITIALIZING);
	} else {
		fdvio_notice("target device magic already set")
		if (FDVIO_SWITCH_STRICT(COLD, INITIALIZING)) {
			fdvio_info("starting re-initialization of device");
		} else {
			fdvio_error("attempt to initialize non-cold device,"
					    " for now I will continue, but if it is not a"
						" accidental magic match, check your code!");
			FDVIO_SWITCH_FORCED(INITIALIZING);
		}
	}

	fdi_xfer_init(&fdvio->xfer);

	fdvio->next_xfer_id = 1;
	fdvio->got_other_side_data = false;
	fdvio->have_sent_our_data = false;

	int res = fdvio_accept_data(fdvio, default_xfer);
	if (res != 0) {
		fdvio_err("device init failed: could not accept xfer data, stopping.");
		goto accept_data_failed;
	}

	if (!FDVIO_SWITCH_STRICT(INITIALIZING, IDLE)) {
		BUG_ON(true);
	}

	fdvio_info("fdvio device initialized");
	return 0;

accept_data_failed:
	FDVIO_SWITCH_FORCED(COLD);
	return res;
}
EXPORT_SYMBOL(fdvio_init);

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END


int fdvio_reset(void __kernel *device
             , struct full_duplex_xfer *default_xfer)
{
}

// API
//
// Closes the device.
// See struct full_duplex_interface description for more info.
__maybe_unused
int fdvio_close(void __kernel *device)
{
	



	fdi_xfer_free(&mirror->xfer);
}
EXPORT_SYMBOL(fdvio_close);


// Is called from rpmsg engine when we receive the inbound message from
// somebody, who is identified by @source. The message destination corresponds
// to the rpmsg device source address.
// @rpdev the underlying rpmsg_device
// @msg the ptr to the message itself
// @msg_len length of the message in bytes
// @private_data some extra data pointer (not used by us).
// @source the address of the source of the message.
//
// RETURNS:
//		0: on success
int fdvio_rpmsg_rcv_cb(struct rpmsg_device *rpdev, void *msg, int msg_len
				, void *private_data, u32 source)
{
	if (IS_ERR_OR_NULL(rpdev)) {
		pr_err("Broken pointer to the rpmsg_device in "__func__"\n");
		return -ENODEV;
	}
	if (IS_ERR_OR_NULL(rpdev->dev)) {
		pr_err("Broken pointer to the rpmsg_device->dev in "__func__"\n");
		return -ENODEV;
	}

	struct fdvio_dev *fdvio = (struct fdvio_dev *)dev_get_drvdata(rpdev->dev);

	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(msg, return -EINVAL);

	// NOTE: for now we don't filter by source
	// TODO: ensure that it is OK or add filtering

	// the xfer kicked-off
	if (FDVIO_SWITCH_STRICT(IDLE, XFER)) {
		fdvio->got_other_side_data = false;
		fdvio->have_sent_our_data = false;
	}

	// and now we 
	if (fdvio->xfer.size_bytes) {

	}
	memcpy(fdvio->xfer.rx_data_buf, msg, msg_len);




}

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN

/*------------------------------ FDVIO DEVICE ------------------------------*/

// Increment the next xfer ID and return the original value.
//
// RETURNS:
// 		the xfer id to assign to the next xfer
int fdvio_set_next_xfer_id(struct fdvio_dev *fdvio)
{
	FDVIO_CHECK_DEVICE(return 0);

	int res = fdvio->next_xfer_id;
	fdvio->next_xfer_id++;
	if (fdvio->next_xfer_id < 0) {
		fdvio->next_xfer_id = 1;
	}
	return res;
}

// Accepts the data given by @xfer as a transfer data (one which will
// next to be sent if client code or other side asks for the xfer).
// @fdvio {VALID PTR} the fdvio device to work with.
// @xfer {VALID PTR} the xfer to accept.
//
// RETURNS:
//      >=0: all fine, the id of the xfer to happen
//      <0: negated error code
int fdvio_accept_data(struct fdvio_dev* fdvio
		, struct __kernel full_duplex_xfer *xfer)
{
	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(xfer, return -EINVAL);

	int res = fdi_deep_xfer_copy(xfer, &fdvio->xfer);
	if (res < 0) {
		return res;
	}

	res = fdi_xfer_unfold(&mirror->xfer);
	if (res < 0) {
		return res;
	}

	return fdvio->xfer.id;
}

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END


// Called
static void mirror_postprocessing_sequence(struct work_struct *work)
{
	struct mirror_xfer_device *mirror = container_of(work
			, struct mirror_xfer_device
			, postprocessing_work);

	if (!mirror->xfer.done_callback) {
		return;
	}

	bool start_immediately = false;
	struct full_duplex_xfer *next_xfer
			= mirror->xfer.done_callback(
				&mirror->xfer
				, mirror->next_xfer_id
				, &start_immediately
				, mirror->xfer.consumer_data);

	if (IS_ERR(next_xfer)) {
		fdmirror_info("Device is halted by consumer request.");
		return;
	}

	if (next_xfer && fdvio_accept_data(mirror, next_xfer) < 0) {
		fdmirror_warn("no memory");
		return;
	}

	if (start_immediately) {
		schedule_work(&mirror->postprocessing_work);
	} else {
		mirror->in_xfer = false;
	}
}

int __mirror_default_data_update_sequence(
		struct mirror_xfer_device *mirror
		, struct full_duplex_xfer *xfer
		, bool force_size_change)
{
	FDMIRROR_CHECK_PTR(mirror, return -EINVAL);
	FDMIRROR_CHECK_PTR(xfer, return -EINVAL);
	FDMIRROR_MIRROR_ON_FINISH(return -EHOSTDOWN);

	bool expected_state = false;
	bool dst_state = true;
	bool res = __atomic_compare_exchange_n(&mirror->in_xfer
			, &expected_state, dst_state, false
			, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);

	if (!res) {
		fdmirror_warn("xfer devicce is busy");
		return -EALREADY;
	}

	if (xfer->size_bytes != mirror->xfer.size_bytes
			&& !force_size_change) {
		fdmirror_warn("will not change xfer size");
		return -EINVAL;
	}

	return fdvio_accept_data(mirror, xfer);
}

/*------------------- MIRROR DEVICE API ----------------------------*/

// API
//
// See struct full_duplex_interface description.
__maybe_unused
int mirror_data_xchange(void __kernel *device
		, struct __kernel full_duplex_xfer *xfer
		, bool force_size_change)
{
	FDMIRROR_DEV_TO_MIRROR;
	FDMIRROR_CHECK_DEVICE(device, return -ENODEV);
	FDMIRROR_MIRROR_ON_FINISH(return -EHOSTDOWN);

	int accept_res = 0;
	if (xfer != NULL) {
		accept_res = __mirror_default_data_update_sequence(
					mirror, xfer
					, force_size_change);
	}
	if (accept_res >= 0) {
		schedule_work(&mirror->postprocessing_work);
	}

	return accept_res;
}
EXPORT_SYMBOL(mirror_data_xchange);

// API
//
// See struct full_duplex_interface description.
__maybe_unused
int mirror_default_data_update(void __kernel *device
		, struct full_duplex_xfer *xfer
		, bool force_size_change)
{
	FDMIRROR_DEV_TO_MIRROR;
	FDMIRROR_CHECK_DEVICE(device, return -ENODEV);
	FDMIRROR_MIRROR_ON_FINISH(return -EHOSTDOWN);
	if (IS_ERR(xfer)) {
		return -EINVAL;
	}

	int accept_res = __mirror_default_data_update_sequence(
				mirror, xfer
				, force_size_change);

	if (accept_res >= 0) {
		mirror->in_xfer = false;
	}

	return accept_res;
}
EXPORT_SYMBOL(mirror_default_data_update);

// API
//
// See struct full_duplex_interface description.
__maybe_unused
bool mirror_is_running(void __kernel *device)
{
	FDMIRROR_DEV_TO_MIRROR;
	FDMIRROR_CHECK_DEVICE(device, return false);
	FDMIRROR_MIRROR_ON_FINISH(return false);
	return mirror->running;
}
EXPORT_SYMBOL(mirror_is_running);


// API
//
// See struct full_duplex_interface description.
__maybe_unused
int mirror_reset(void __kernel *device
		, struct full_duplex_xfer *default_xfer)
{
	mirror_close(device);
	return mirror_init(device, default_xfer);
}
EXPORT_SYMBOL(mirror_reset);

/*------------ FULL DUPLEX INTERFACES DEFINITION -------------------*/

const struct full_duplex_sym_iface mirror_duplex_iface = {
	.data_xchange = &mirror_data_xchange
	, .default_data_update = &mirror_default_data_update
	, .is_running = &mirror_is_running
	, .init = &mirror_init
	, .reset = &mirror_reset
	, .close = &mirror_close
};

// API
//
// Returns ptr to the full duplex device interface object
// which defines mirror device interface.
//
// RETURNS:
//      valid ptr to struct full_duplex_sym_iface with all
//      fields filled
__maybe_unused
const struct full_duplex_sym_iface *full_duplex_mirror_iface(void)
{
	return &mirror_duplex_iface;
}
EXPORT_SYMBOL(full_duplex_mirror_iface);

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN
// API
//
// This guy gets called when kernel finds a new device on the rpmsg bus,
// or when our driver has just been plugged in.
// @dev the detected device
//
// NOTE: the client driver will be attached later on, the fdvio init goes
//      without client driver available, the default xfer is 0 (0 size).
//
// RETURNS: 
//      0: success
//      !=0: negated error code
__maybe_unused
static int fdvio_probe(struct rpmsg_device *rpdev)
{
	if (IS_ERR_OR_NULL(rpdev)) {
		pr_err("Broken pointer to the rpmsg_device in "__func__"\n");
		return -ENODEV;
	}
	if (IS_ERR_OR_NULL(rpdev->dev)) {
		pr_err("Broken pointer to the rpmsg_device->dev in "__func__"\n");
		return -ENODEV;
	}
	if (IS_ERR_OR_NULL(rpdev->ept)) {
		pr_err("Broken pointer to the rpmsg_device->ept in "__func__"\n");
		return -EINVAL;
	}

	dev_info(&rpdev->dev, "fdvio: new device, channel: 0x%x -> 0x%x\n"
			 , rpdev->src, rpdev->dst);

	struct fdvio_dev *fdvio = (*struct fdvio_dev)kmalloc(
									sizeof(struct fdvio_dev), GFP_KERNEL);
	int res = 0;
	if (IS_ERR_OR_NULL(fdvio)) {
		dev_err(&rpdev-dev, "fdvio: failed to allocate memory for fdvio_dev.\n");
		res = -ENOMEM;
		goto fdvio_alloc_failed;
	}

	dev_set_drvdata(rpdev->dev, fdvio);

	// NOTE: the default xfer is set to be empty, when the master driver
	//  comes, it will set the proper xfer.
	struct full_duplex_xfer def_xfer = {0};
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END
// TODO: add the default xfer callbacks?
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN

	res = fdvio_init(fdvio, &def_xfer);
	if (!res) {
		dev_err(&rpdev-dev, "fdvio: initialization failed: errno: %d\n"
				, res);
		goto fdvio_init_failed;
	}

	// NOTE: after return we might immediately get the messages from the
	//    other side, which will be effectively dropped until the client
	//    driver gets bound to us.
	return 0;

fdvio_init_failed:
	dev_set_drvdata(rpdev->dev, NULL);
	kfree(fdvio);
fdvio_alloc_failed:
	return res;
}

// API
//
// Detatches the fdvio driver from the fdvio device.
//
// NOTE: due to device linking we're guaranteed that all clients of fdvio
//      driver are already removed.
__maybe_unused
static void fdvio_remove(struct rpmsg_channel *rpdev)
{
	dev_info(&rpdev->dev, "fdvio: removing device, channel: 0x%x -> 0x%x\n"
			 , rpdev->src, rpdev->dst);

	int res = 0;
	struct fdvio_dev *fdvio = (struct fdvio_dev *)dev_get_drvdata(rpdev->dev);

	if (IS_ERR_OR_NULL(fdvio)) {
		dev_err(&rpdev->dev, "fdvio: rpdev has no valid ptr do fdvio dev."
						" It will not be a graceful close.\n");
		res = -ENODEV;
	} else {
		res = fdvio_close(fdvio);

		if (!res) {
			dev_err(&rpdev->dev, "fdvio: fdvio_close failed, errno: %d\n", res);
		}
	}

	dev_set_drvdata(rpdev->dev, NULL);

	dev_err(&rpdev->dev, "fdvio: closed with result: %d\n", res);
}

static struct rpmsg_device_id fdvio_id_table[] = {
	{ .name = "fdvio", .driver_data = 0 }
	, { }
	,
};
MODULE_DEVICE_TABLE(rpmsg, fdvio_id_table);


// Registering the driver as rpmsg driver
static struct rpmsg_driver fdvio_driver = {
	.drv.name       = "fdvio",
	.id_table       = fdvio_id_table,
	.probe          = fdvio_probe,
	.callback       = fdvio_rpmsg_rcv_cb,
	.remove         = fdvio_remove,
};
module_rpmsg_driver(fdvio_driver);

MODULE_DESCRIPTION("Full duplex VirtIO (rpmsg-based) device");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END
