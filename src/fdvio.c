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
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/rpmsg.h>
#include <linux/proc_fs.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>

#include <linux/full_duplex_interface.h>

// the level of debugging
// 0 - no debug
#define FDVIO_DEBUG_LEVEL 0

/* --------------------- UTILITIES SECTION ----------------------------- */


#define FDVIO_LOG_PREFIX "fdvio: "


#define fdvio_emerg(fmt, ...)                                               \
    dev_emerg(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"       \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_crit(fmt, ...)                                           \
    dev_crit(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"        \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_alert(fmt, ...)                                          \
    dev_alert(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"       \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_err(fmt, ...)                                            \
    dev_err(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"         \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_warn(fmt, ...)                                           \
    dev_warn(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"        \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_notice(fmt, ...)                                         \
    dev_notice(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"      \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_info(fmt, ...)                                           \
    dev_info(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"        \
              , __func__, __LINE__, ##__VA_ARGS__)
#if FDVIO_DEBUG_LEVEL > 0
#define fdvio_trace(fmt, ...)                                           \
    dev_info(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"        \
              , __func__, __LINE__, ##__VA_ARGS__)
#else
    #define fdvio_trace(fmt, ...)
#endif


#define fdvio_emerg_rlim(fmt, ...)                                               \
    dev_emerg_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"\
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_crit_rlim(fmt, ...)                                           \
    dev_crit_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n" \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_alert_rlim(fmt, ...)                                          \
    dev_alert_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"\
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_err_rlim(fmt, ...)                                            \
    dev_err_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"  \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_warn_rlim(fmt, ...)                                           \
    dev_warn_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n" \
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_notice_rlim(fmt, ...)                                         \
    dev_notice_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"\
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_info_rlim(fmt, ...)                                           \
    dev_info_ratelimited(&fdvio->rpdev->dev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n" \
              , __func__, __LINE__, ##__VA_ARGS__)


#define CAST_DEVICE_TO_FDVIO                                        \
        struct fdvio_dev *fdvio = (struct fdvio_dev *)device;
#define FROM_PLATFORM_DEV_TO_FDVIO                                  \
        struct fdvio_dev *fdvio = ((struct full_duplex_device *)    \
                                       dev_get_drvdata(             \
											(struct device*)device))->dev;

#define FDVIO_CHECK_DEVICE(error_action)                    \
	if (IS_ERR_OR_NULL(fdvio)) {                            \
		fdvio_err("no device;");                            \
		error_action;                                       \
	}
#define FDVIO_CHECK_KERNEL_DEVICE(error_action)             \
	if (IS_ERR_OR_NULL(fdvio->rpdev)) {                     \
		fdvio_err("no kernel device;");                     \
		error_action;                                       \
	}
#define FDVIO_CHECK_PTR(ptr, error_action)                     \
	if (IS_ERR_OR_NULL(ptr)) {                                 \
		fdvio_err(#ptr"(%px): ptr error\n", ptr);              \
		error_action;                                          \
	}
#define FDVIO_ON_FINISH(action)                   \
	if (fdvio->finishing) {                       \
		action;                                   \
	}

// Bool value, true, when switch occured
#ifdef FDVIO_DEBUG
#define FDVIO_SWITCH_STRICT(from, to)                          \
	(fdvio_trace(" -> "#to), atomic_cmpxchg(&fdvio->state,     \
					FDVIO_STATE_##from,                        \
					FDVIO_STATE_##to) == FDVIO_STATE_##from)
#else
#define FDVIO_SWITCH_STRICT(from, to)                          \
	(atomic_cmpxchg(&fdvio->state,                             \
					FDVIO_STATE_##from,                        \
					FDVIO_STATE_##to) == FDVIO_STATE_##from)
#endif

#define FDVIO_SWITCH_FORCED(to)                          \
	atomic_set(&fdvio->state, FDVIO_STATE_##to)
#define FDVIO_STATE_IS(st_name)                          \
	(atomic_read(&fdvio->state) == FDVIO_STATE_##st_name)
#define FDVIO_STATE()                          \
	(atomic_read(&fdvio->state))

#ifdef FDVIO_DEBUG
#define FDVIO_ASSERT_STATE(state)                                          \
	if (atomic_read(&fdvio->state) != FDVIO_STATE_##state) {               \
		fdvio_crit("assertion failed: unexpected state: != to "#state);    \
		BUG_ON(true);								                       \
	}
#define FDVIO_ASSERT_DEVICE()                                        \
	if (IS_ERR_OR_NULL(fdvio)) {                                     \
		fdvio_crit("assertion failed: broken fdvio device pointer"); \
		BUG_ON(true);								                 \
	}
#define FDVIO_ASSERT_PTR(ptr)                            \
	if (IS_ERR_OR_NULL(ptr)) {                           \
		fdvio_crit("assertion failed: broken ptr "#ptr); \
		BUG_ON(true);								     \
	}
#else
#define FDVIO_ASSERT_STATE(state)
#define FDVIO_ASSERT_DEVICE()
#define FDVIO_ASSERT_PTR(ptr)
#endif


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

// The timeout for waiting for the other side data after we have sent our.
#ifndef FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC
    #define FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC 30
#endif
// How much time we sleep ignoring all if error occured
#ifndef FDVIO_ERROR_SILENCE_TIME_MSEC
    #define FDVIO_ERROR_SILENCE_TIME_MSEC 37
#endif

#define FDVIO_DEV_NAME_MAX_LEN 80

// This guy is used if customer didn't provide its RX buffer
#define FDVIO_OWN_RX_BUFFER_SIZE_BYTES 512

#ifndef FDVIO_WORKQUEUE_MODE
#define FDVIO_WORKQUEUE_MODE FDVIO_WQ_PRIVATE
#endif

#define FDVIO_WQ_SYSTEM 0
#define FDVIO_WQ_SYSTEM_HIGHPRI 1
#define FDVIO_WQ_PRIVATE 2

// Comparator
#define FDVIO_WQ_MODE_MATCH(x)		\
	FDVIO_WORKQUEUE_MODE == FDVIO_WQ_##x

#ifndef FDVIO_WORKQUEUE_MODE
#error FDVIO_WORKQUEUE_MODE must be defined to \
		one of [FDVIO_WQ_SYSTEM, FDVIO_WQ_SYSTEM_HIGHPRI, \
		FDVIO_WQ_PRIVATE].
#endif

// The cold-and-dark state of the driver - before initialization was even
// carried out.
#define FDVIO_STATE_COLD 0
// First state after COLD. We enter it when device is initialized but
// not yet started.
#define FDVIO_STATE_INITIALIZED 1
// Last state before COLD. We enter it right upon the shut down start.
#define FDVIO_STATE_SHUTTING_DOWN 2
// State, when nothing is happening, no one waits for anything, no tranfers
// are executing, no timeouts active. We just sit and wait for an external
// kick from either side.
// NOTE: right before we enter the IDLE state all xfer flags must be dropped 
//     like "got other side data" and "sent our data" flags.
#define FDVIO_STATE_IDLE 3
// The state in which we push the outgoing data:
// * send out our data and
// * start the timeout timer
// * then switch to the XFER_RX state
//
// we switch to this state by
// * __fdvio_rpmsg_rcv_cb callback from the other side.
//   NOTE: this event comes from a callback registered by: rpmsg_create_ept(...)
// * Upper layer kicks us with data xfer request.
//   NOTE: this is done in data_xchange(...) function implementation AND
//      in the xfer_done/xfer_fail callbacks.
#define FDVIO_STATE_XFER_TX 4
// The state in which we get the inbound data:
// * stop timer
// * call xfer_done
// * then switch to IDLE state
//
// to this state we come from XFER_TX state automatically.
#define FDVIO_STATE_XFER_RX 5
// This state indicates an error in fdvio operation. Normally we need to notify
// the other side about the error and get out of this state as soon as possible.
#define FDVIO_STATE_ERROR 6


// This value is used to identify if the instance of the driver data
// was already initialized once, and then the data fields there are expected
// to make sense. Otherwise we ignore the data fields on init, cause they
// are expected to be garbage.
//
// NOTE: this is not the absolute protection, but mostly the debugging aid.
#define FDVIO_MAGIC 0x83cad137

// The sizes of the xfers from both sides are not matching.
// Example: we're expecting the xfer of 10 bytes, and the other side sends
//      us 12 bytes.
#define FDVIO_ERROR_XFER_SIZE_MISMATCH 1
// We have got more than one inbound message within a single xfer, this normally
// indicates a sync loss, or basically that the other side dropped the
// previous xfer due to timeout in waiting for our response.
#define FDVIO_ERROR_MULTIPLE_RECEIVE 2
// This error is set upon the error from the rpmsg. For example when the
// rpmsg faces the timeout of waiting for free buffers in the output VQ.
#define FDVIO_ERROR_RPMSG 3
// This error is used to indicate that there was no switch between states
// cause expectation state didn't match (atomic switch failed)
#define FDVIO_ERROR_NO_SWITCH 4
// This error is used in case the other side didn't provide the
// data on time (after we have sent our data)
#define FDVIO_ERROR_OTHER_SIDE_TIMEOUT 5
// The rpmsg send data failed.
#define FDVIO_ERROR_SEND_FAILED 6
// Should not happen, unless there is a bug
#define FDVIO_ERROR_LOGIC 7
// The method, function not implemented
#define FDVIO_ERROR_NOT_IMPLEMENTED 8
// No current xfer provided
#define FDVIO_ERROR_NO_XFER 9


// pre-declaration
static struct rpmsg_driver fdvio_driver;

// The device itself
// @magic the field where the FDVIO_MAGIC should be written upon the
//  initialization start.
// @state the current state of the device
// @dev the corresponding rpmsg device record in the kernel device facilities.
// @xfer the current xfer data - this data is also used for default xfer
//      data storage.
// @next_xfer_id stores the next xfer id - when xfer is just done, its
// 		value used to set the next xfer id, and then it gets incremented.
// @delayed_xfer_request is set to true when upper layer asked for a xfer
//      while we were busy.
// @wait_timeout_timer the other side wait timeout timer,
//      it is enabled every time when we start waiting for the
//      other side data, and is disabled every time we finish
//      the waiting.
// @pdev The platform device we register on creation to make it working
//    with ICCom. It works only as a formal adapter to the ICCom expectations.
//    NOTE: later this to be polished.
// @fdtd the full duplex transport device.
//      * .dev points to fdvio
//		NOTE: the platform driver data points to the @tdtd.
struct fdvio_dev {
	uint32_t magic;
	atomic_t state; 
	struct rpmsg_device *rpdev;
	
	// never owns the data
	struct full_duplex_xfer *xfer;

	int next_xfer_id;

	bool delayed_xfer_request;

	struct timer_list wait_timeout_timer;

	struct platform_device *pdev;
	// drv_data points to this struct.
	struct full_duplex_device fdtd;

#if FDVIO_WQ_MODE_MATCH(PRIVATE)
	struct workqueue_struct *work_queue;
#endif

	struct work_struct recover_work;

	char own_rx_buf[FDVIO_OWN_RX_BUFFER_SIZE_BYTES];
};

/*---------------------- PRE DECLARATIONS ----------------------------*/

int fdvio_data_xchange(void __kernel *device
                    , struct __kernel full_duplex_xfer *xfer
                    , bool force_size_change);
int fdvio_default_data_update(void __kernel *device
                           , struct full_duplex_xfer *xfer
                           , bool force_size_change);
bool fdvio_is_running(void __kernel *device);
int fdvio_start(void __kernel *device
		, struct full_duplex_xfer *initial_xfer);
int fdvio_stop(void __kernel *device);
int fdvio_reset(void __kernel *device
             , struct full_duplex_xfer *initial_xfer);
int __fdvio_goto_xfer(
		struct fdvio_dev *fdvio
		, struct __kernel full_duplex_xfer *xfer);
void __fdvio_goto_error_and_idle(struct fdvio_dev *fdvio
		, int error_code);
static inline void __fdvio_restart_timeout_timer(struct fdvio_dev *fdvio);
static inline void __fdvio_stop_timeout_timer(struct fdvio_dev *fdvio);
static inline void __fdvio_stop_timeout_timer_sync(struct fdvio_dev *fdvio);
static void __fdvio_other_side_wait_timeout_handler(struct timer_list *t);
int __fdvio_rpmsg_rcv_cb(struct rpmsg_device *rpdev, void *msg, int msg_len
				, void *private_data, u32 source);
static inline int __fdvio_init_workqueue(
		struct fdvio_dev *const fdvio);
static inline void __fdvio_close_workqueue(
		struct fdvio_dev *const fdvio);
static inline void __fdvio_schedule_work(
		struct fdvio_dev *const fdvio
		, struct work_struct *work);
static inline void __fdvio_cancel_work_sync(
		struct fdvio_dev *const fdvio
		, struct work_struct *work);
int __fdvio_set_next_xfer_id(struct fdvio_dev *fdvio);
int __fdvio_accept_data(struct fdvio_dev* fdvio
		, struct __kernel full_duplex_xfer *xfer);
int __fdvio_init(void __kernel *device);
int __fdvio_close(void __kernel *device);

const struct full_duplex_sym_iface *full_duplex_fdvio_iface(void);

static int fdvio_probe(struct rpmsg_device *rpdev);
static void fdvio_remove(struct rpmsg_device *rpdev);

/*---------------------- FDVIO DEVICE API ----------------------------*/

// In short: this function is called by consumer driver to trigger the
// xfer.
// NOTE: in comparison to SymSPI we will not copy the xfer, but actually
//     use one which is provided (expectation is that consumer will not
//     operate the xfer data until the xfer result is available, or to update
//     the xfer the separate xfer will be created and pointed to by @xfer
//     here)
// See the Full Duplex xfer interface for full description.
// @device is a pointer to the fdvio device
//
// STATUS:
//     * IDLE->XFER
__maybe_unused
int fdvio_data_xchange(void __kernel *device
                    , struct __kernel full_duplex_xfer *xfer
                    , bool force_size_change)
{
	CAST_DEVICE_TO_FDVIO;
	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);

	int res = __fdvio_goto_xfer(fdvio, xfer);

	if (res == 0) {
		// all fine, we have sent our data, started the timer, and moved to the
		// XFER_RX state and started waiting for the other side data.
		return 0;
	} else if (res == -FDVIO_ERROR_NO_SWITCH) {
		// there was no switch cause we're were not in idle, so we
		// schedule the xfer later on
		fdvio->delayed_xfer_request = true;
		return 0;
	}

	return res;
}
EXPORT_SYMBOL(fdvio_data_xchange);

// Updates the default data.
// @device is a pointer to the fdvio device
__maybe_unused
int fdvio_default_data_update(void __kernel *device
                           , struct full_duplex_xfer *xfer
                           , bool force_size_change)
{
	CAST_DEVICE_TO_FDVIO;
	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);
	(void)(xfer);
	(void)(force_size_change);

	// TODO: ACTUALLY IMPLEMENT IT (iccom started to use it):
	//  we can replace the default data if the package is not yet sent, cause
	//  was not requested to start immediately by protocol driver.

	return -ENOSYS;
}
EXPORT_SYMBOL(fdvio_default_data_update);

// @device is a pointer to the fdvio device
// RETURNS: true if fdvio is in one of running states
__maybe_unused
bool fdvio_is_running(void __kernel *device)
{
	CAST_DEVICE_TO_FDVIO;
	FDVIO_CHECK_DEVICE(return false);
	FDVIO_CHECK_KERNEL_DEVICE(return false);

	int32_t st = FDVIO_STATE();
	return (st != FDVIO_STATE_COLD) && (st != FDVIO_STATE_SHUTTING_DOWN)
		&& (st != FDVIO_STATE_INITIALIZED);
}
EXPORT_SYMBOL(fdvio_is_running);

// API
// Short: starts the initialized fdvio device. Basically really launches
// 		it. After this call returns successfully, one can receive the
// 		messages from the other side.
//
// @device {valid ptr to initialized device}  the already allocated and
//      initialized fdvio_dev.
// @initial_xfer {valid ptr to the valid xfer} the proper valid xfer pointer
__maybe_unused
int fdvio_start(void __kernel *device
		, struct full_duplex_xfer *initial_xfer)
{
	CAST_DEVICE_TO_FDVIO;
    FDVIO_CHECK_DEVICE(return -ENODEV);
    FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(fdvio->rpdev, return -ENODEV);
	FDVIO_CHECK_PTR(initial_xfer, return -EINVAL);

	fdvio_info("starting device: %px", device);

	if (FDVIO_STATE() != FDVIO_STATE_INITIALIZED) {
		fdvio_info("Device must be in initialized state: %px,\n"
                   " can not start, actual state: %d."
					, device, FDVIO_STATE());
		return -EFAULT;
	}

	int res = __fdvio_accept_data(fdvio, initial_xfer);
	if (res != 0) {
		fdvio_err("failed to accept the initial data, xfer size: %zu"
                  ", xfer tx data: %px, xfer rx buf: %px", initial_xfer->size_bytes
                  , initial_xfer->data_tx, initial_xfer->data_rx_buf);
		goto accept_data_failed;
	}

	if (!FDVIO_SWITCH_STRICT(INITIALIZED, IDLE)) {
		fdvio_info("Failed to switch INITIALIZED->INIT: %px, can not start."
					, device);
		res = -EFAULT;
		goto switch_failed;
	}

	fdvio_info("fdvio device initialized: %px", device);
	return 0;

switch_failed:
	fdvio->xfer = NULL;
accept_data_failed:
	return res;
}
EXPORT_SYMBOL(fdvio_start);

// API
//
// Closes the device.
// See struct full_duplex_interface description for more info.
// @device is a pointer to the fdvio device
//
// RETURNS:
// 		>=0: all ok even if device is already or closed
// 			or never initialized
// 		<0: negated error code
__maybe_unused
int fdvio_stop(void __kernel *device)
{
	CAST_DEVICE_TO_FDVIO;
    FDVIO_CHECK_DEVICE(return -ENODEV);
    FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(fdvio->rpdev, return -ENODEV);

	fdvio_info("fdvio device (%px) stopping ...", device);

	if (fdvio->magic != FDVIO_MAGIC) {
		fdvio_info("dev magic doesn't match, will skip closing.");
		return 0;
	}

	while (true) {
		int32_t st = FDVIO_STATE();
		if (st == FDVIO_STATE_COLD) {
			fdvio_warn("We're already cold and dark, will not stop.");
			return 0;
		}
		if (st == FDVIO_STATE_SHUTTING_DOWN) {
			fdvio_warn("We're already going down, will not stop.");
			return -EBUSY;
		}
		if (st == FDVIO_STATE_INITIALIZED) {
			fdvio_info("Already stopped.");
			return 0;
		}

		if (FDVIO_SWITCH_STRICT(XFER_TX, SHUTTING_DOWN)
				|| FDVIO_SWITCH_STRICT(XFER_RX, SHUTTING_DOWN)
				|| FDVIO_SWITCH_STRICT(ERROR, SHUTTING_DOWN)
				|| FDVIO_SWITCH_STRICT(IDLE, SHUTTING_DOWN)) {
			break;
		}
	}

	__fdvio_stop_timeout_timer_sync(fdvio);

	__fdvio_cancel_work_sync(fdvio, &fdvio->recover_work);

	fdvio->xfer = NULL;

	(void)FDVIO_SWITCH_STRICT(SHUTTING_DOWN, INITIALIZED);
	fdvio_info("fdvio device stopped: %px", device);

    return 0;
}
EXPORT_SYMBOL(fdvio_stop);

// Just reset it. Stop and start it again.
// @device is a pointer to the fdvio device
__maybe_unused
int fdvio_reset(void __kernel *device
             , struct full_duplex_xfer *initial_xfer)
{
	fdvio_stop(device);
	return fdvio_start(device, initial_xfer);
}
EXPORT_SYMBOL(fdvio_reset);


/*---------------------- STATE SWITCHING ROUTINES --------------------*/

// Switches the state from IDLE to XFER_TX and then to XFER_RX and does all
// what is needed in XFER_TX mode.
// @fdvio {proper ptr to fdvio dev} our device
// @xfer the pointer to new xfer to work with (if NULL, then current xfer
//    remains).
// 
// RETURNS:
// 	0: success
// 	<0: negated error code on failure
//		* FDVIO_ERROR_NO_SWITCH means that there was no switch
//		  cause we were not in idle state.
int __fdvio_goto_xfer(
		struct fdvio_dev *fdvio
		, struct __kernel full_duplex_xfer *xfer)
{
	FDVIO_ASSERT_DEVICE();
	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);

	if (!FDVIO_SWITCH_STRICT(IDLE, XFER_TX)) {
		fdvio_trace("no switch, state: %d", FDVIO_STATE());
		return -FDVIO_ERROR_NO_SWITCH;
	}

	int res = __fdvio_accept_data(fdvio, xfer);
	if (res != 0) {
		fdvio_err("new xfer could not be accepted, retaining original one");
		// NOTE: nothing really to do here, we just keep the original xfer.
	}

	if (IS_ERR_OR_NULL(fdvio->xfer)) {
		fdvio_err("current xfer is NULL, going back to IDLE");
		(void)FDVIO_SWITCH_STRICT(XFER_TX, IDLE);
		return -FDVIO_ERROR_NO_XFER;
	}

	fdvio->delayed_xfer_request = false;

	fdvio_trace("sending msg 0x%x -> 0x%x, data size %zu"
				, fdvio->rpdev->src, fdvio->rpdev->dst
				, fdvio->xfer->size_bytes);

	res = rpmsg_send(fdvio->rpdev->ept, fdvio->xfer->data_tx
				, fdvio->xfer->size_bytes);
	if (res != 0) {
		fdvio_err("The rpmsg_send 0x%x -> 0x%x, data size %zu failed with"
					" code: %d", fdvio->rpdev->src, fdvio->rpdev->dst
					, fdvio->xfer->size_bytes, res);
		__fdvio_goto_error_and_idle(fdvio, FDVIO_ERROR_SEND_FAILED);
		return -FDVIO_ERROR_SEND_FAILED;
	}

	__fdvio_restart_timeout_timer(fdvio);

	if (!FDVIO_SWITCH_STRICT(XFER_TX, XFER_RX)) {
		__fdvio_goto_error_and_idle(fdvio, FDVIO_ERROR_SEND_FAILED);
		return -FDVIO_ERROR_LOGIC;
	}

	return 0;
}

// handles the error in a sync way and goes to the IDLE state,
// main job of the routine:
// * to switch to the error state in a strict way
// * stop all timers
// * clean up the state
// * report an error
// * wait for silence time (usually about 50 ms)
// * get back to IDLE state
// @fdvio {proper ptr to fdvio dev} our device
// @error_code the error code provided by caller
//
// NOTE: for now, doesn't handle the startup/shutdown states,
// 		like COLD, INITIALIZED, SHUTTING_DOWN - not expected to be needed.
void __fdvio_goto_error_and_idle(struct fdvio_dev *fdvio
		, int error_code)
{
	FDVIO_CHECK_DEVICE(return);
	FDVIO_CHECK_KERNEL_DEVICE(return);

	while (true) {
		int32_t st = FDVIO_STATE();
		if (st == FDVIO_STATE_COLD
				|| st == FDVIO_STATE_INITIALIZED
				|| st == FDVIO_STATE_SHUTTING_DOWN
				|| st == FDVIO_STATE_IDLE) {
			fdvio_warn("%d state not to be recovered.", st);
			return;
		}
		if (st == FDVIO_STATE_ERROR) {
			fdvio_warn("Skipping nested error recovery.");
			return;
		}

		if (FDVIO_SWITCH_STRICT(XFER_TX, ERROR)
					|| FDVIO_SWITCH_STRICT(XFER_RX, ERROR)) {

			fdvio_err("Recovering from the error: %d", error_code);

			// stop timer
			__fdvio_stop_timeout_timer_sync(fdvio);

			// wait idle-on-error time, which also signals our error state to the
			// other side
			// NOTE: we idling only if the error is not the size mismatch,
			//     cause size mismatch can be instantly processed, cause
			//     both sides see it the same.
			if (error_code != FDVIO_ERROR_XFER_SIZE_MISMATCH) {
				fdvio_trace("Going sleep for recovery: %d"
                            , FDVIO_ERROR_SILENCE_TIME_MSEC);
				msleep(FDVIO_ERROR_SILENCE_TIME_MSEC);
				fdvio_trace("Got some sleep.");
			}

			// NOTE:
			// HERE ONE CAN ADD SENDING SOME ERROR INDICATION
			// SPECIAL PACKAGE TO THE OTHER SIDE, PROBABLY EVEN
			// ONE WITH 0 SIZE

			// report to consumer
			struct full_duplex_xfer *next_xfer = NULL;
			bool start_immediately = false;

			// NOTE: the xfer DOES NOT own the data
			fdvio->xfer->data_rx_buf = NULL;
			if (!IS_ERR_OR_NULL(fdvio->xfer->fail_callback)) {
				next_xfer = fdvio->xfer->fail_callback(
								fdvio->xfer
								, fdvio->next_xfer_id
								, error_code
								, fdvio->xfer->consumer_data);
			}
			
			if (IS_ERR(next_xfer)) {
				fdvio_info("Device is halted by consumer request.");
				return;
			}

			int res = __fdvio_accept_data(fdvio, next_xfer);
			if (res != 0) {
				fdvio_err("new xfer could not be accepted, retaining original one");
				// NOTE: nothing really to do here, we just keep the original xfer.
			}
	
			(void)FDVIO_SWITCH_STRICT(ERROR, IDLE);

			// FIXME: WARNING: TODO: probability of the recursion here
			// * we start transmission
			// * send fails
			// * we call error recovery
			// * we wait, do the recovery and start transmission again
			if (start_immediately || fdvio->delayed_xfer_request) {
				fdvio_data_xchange(fdvio, NULL, false);
			}

			return;
		}
	}
}

/*-------------------------- TIMERS CTL BLOCK ------------------------*/


// Helper.
// Starts/restarts timeout timer
//
// CONTEXT:
//      any
static inline void __fdvio_restart_timeout_timer(struct fdvio_dev *fdvio)
{
	const unsigned long expiration_time_jf
		= jiffies + msecs_to_jiffies(FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC);
	mod_timer(&fdvio->wait_timeout_timer, expiration_time_jf);
	fdvio_trace(
		    "timer set: in %d ms, in %lu jiffies"
		    " (at %lu jiffies), timer: %px, now: %lu jiffies"
		    , FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC
		    , expiration_time_jf >= jiffies ? (expiration_time_jf - jiffies) : 0
		    , expiration_time_jf
		    , &fdvio->wait_timeout_timer
		    , jiffies);
	if (timer_pending(&fdvio->wait_timeout_timer)) {
		fdvio_trace(
			    "timer status: pending at %lu jiffies, now: %lu jiffies"
			    , fdvio->wait_timeout_timer.expires
			    , jiffies);
	} else {
		fdvio_trace("timer status: idle");
	};
}

// Helper.
// Stops timeout timer. If timer function executes doesn't wait for them.
//
// CONTEXT:
//      any
static inline void __fdvio_stop_timeout_timer(struct fdvio_dev *fdvio)
{
	del_timer(&fdvio->wait_timeout_timer);
	fdvio_trace("Timer stop");
}

// Helper.
// Stops timeout timer and waits for all timer functions executions
// are done.
//
// CONTEXT:
//      sleepable
static inline void __fdvio_stop_timeout_timer_sync(struct fdvio_dev *fdvio)
{
	del_timer_sync(&fdvio->wait_timeout_timer);
	fdvio_trace("Timer stop (sync)");
}

/*---------------------- NON-API ASYNC ENTRY POINTS ------------------*/


// Called by timeout timer. Launches error recovery on timeout.
//
// NOTE: this guy is called in IRQ context
static void __fdvio_other_side_wait_timeout_handler(struct timer_list *t)
{
	struct fdvio_dev *fdvio = from_timer(fdvio, t, wait_timeout_timer);

	fdvio_trace("Timeout: fdvio dev: %px, sheduling recovery.", fdvio);

	FDVIO_CHECK_DEVICE(return);
	FDVIO_CHECK_KERNEL_DEVICE(return);

	__fdvio_schedule_work(fdvio, &fdvio->recover_work);
}

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
//		0: always
//
// CONTEXT: sleepable (this function might sleep)
// 		this function is expected to be called from the workqueue
// 		of the rpmsg device, so if any error is faced, we can handle it
// 		right in place, without sitting for too long in the bottom half.
//
// STATUS:
//     * IDLE->XFER->IDLE
int __fdvio_rpmsg_rcv_cb(struct rpmsg_device *rpdev, void *msg, int msg_len
				, void *private_data, u32 source)
{
	if (IS_ERR_OR_NULL(rpdev)) {
		pr_err("Broken ptr: rpmsg_device in %s\n", __func__);
		return -ENODEV;
	}
	if (IS_ERR_OR_NULL(&rpdev->dev)) {
		pr_err("Broken ptr: rpmsg_device->dev in %s\n", __func__);
		return -ENODEV;
	}

	struct fdvio_dev *fdvio = (struct fdvio_dev *)dev_get_drvdata(&rpdev->dev);

	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(msg, return -EINVAL);
	FDVIO_CHECK_PTR(rpdev->ept, return -EINVAL);

	fdvio_trace("got the data from the other side: src: %d, msg len: %d"
                , source, msg_len);

	// trying to initialize the new xfer, send out our data and start timer.
	int res = __fdvio_goto_xfer(fdvio, NULL);

	if (res != 0 && res != -FDVIO_ERROR_NO_SWITCH) {
		// NOTE: no error recovery here, cause it will be done by
		// 		the __fdvio_goto_xfer routine internally
		return 0;
	}

	// RX sequence here

	fdvio_trace("waiting for XFER_RX state");

	// wait for the XFER_RX state, which indicates
	// that TX part of the sequence is done
	while (true) {
		if (FDVIO_STATE_IS(XFER_RX)) {
			break;
		}
		// the state drifted away, say due to error, or timeout
		if (FDVIO_STATE() != FDVIO_STATE_XFER_TX
				&& FDVIO_STATE() != FDVIO_STATE_XFER_RX) {
			// NOTE: no error recovery here, cause if we managed to
			// 	drift the state, this means it gone through error
			// 	condition, so we just return.
			return 0;
		}
		usleep_range(100, 200);
	};

	// now we can process our incoming data and wrap up the xfer

	__fdvio_stop_timeout_timer_sync(fdvio);

	// No need for secondary check to cover the case when timer was triggered
	// in such a way that: timer set; timer triggers; timer reaches
	// 		the error state setting;  STATE -> XFER_TX; 
	// 		while loop unlocks; timer sets error state;
	// cause error handling uses the switch to switch the states, not the
	// forced switch.

	if (fdvio->xfer->size_bytes != msg_len) {
		__fdvio_goto_error_and_idle(fdvio, FDVIO_ERROR_XFER_SIZE_MISMATCH);
		return 0;
	}

	struct full_duplex_xfer *next_xfer = NULL;
	bool start_immediately = false;

	// NOTE: the xfer DOES NOT own the data
	fdvio->xfer->data_rx_buf = msg;
	if (!IS_ERR_OR_NULL(fdvio->xfer->done_callback)) {
		next_xfer = fdvio->xfer->done_callback(
                        fdvio->xfer
                        , fdvio->next_xfer_id
                        , &start_immediately
                        , fdvio->xfer->consumer_data);
	}
	// we must drop it instantly, as long as we don't own the data
	// and client code already processed it
	fdvio->xfer->data_rx_buf = NULL;
	
	if (IS_ERR(next_xfer)) {
		fdvio_info("Device is halted by consumer request.");
		return 0;
	}

	res = __fdvio_accept_data(fdvio, next_xfer);
	if (res != 0) {
		fdvio_err("new xfer could not be accepted, retaining original one");
		// NOTE: nothing really to do here, we just keep the original xfer.
	}
	
	(void)FDVIO_SWITCH_STRICT(XFER_RX, IDLE);

	// NOTE: this will not recurse, cause when reached the TX state
	// 	it will send our data, start timer and return.
	if (start_immediately || fdvio->delayed_xfer_request) {
		fdvio_data_xchange(fdvio, NULL, false);
	}

	return 0;
}


/*------------------------------ FDVIO HELPERS -----------------------------*/

static void __fdvio_recovery_sequence_wrapper(struct work_struct *work);
// Helper.
// Inits the workqueue which is to be used by Fdvio
// in its current configuration. If we use system-provided
// workqueu - does nothing.
//
// RETURNS:
//      >= 0     - on success
//      < 0     - negative error code
//
// ERRORS:
//      FDVIO_ERROR_WORKQUEUE_INIT
static inline int __fdvio_init_workqueue(
		struct fdvio_dev *const fdvio)
{
#if FDVIO_WQ_MODE_MATCH(SYSTEM)
	fdvio_info("using system wq");
	(void)fdvio;
	return 0;
#elif FDVIO_WQ_MODE_MATCH(SYSTEM_HIGHPRI)
	fdvio_info("using system_highpri wq");
	(void)fdvio;
	return 0;
#elif FDVIO_WQ_MODE_MATCH(PRIVATE)
	fdvio_info("using private wq");
	fdvio->work_queue = alloc_workqueue("fdvio", WQ_HIGHPRI, 0);

	if (fdvio->work_queue) {
		return 0;
	} else {
		fdvio_err("the private work queue init failed");
		return -ENODEV;
	}
#endif
}

// Helper.
// Closes the workqueue which was used by Fdvio
// in its current configuration. If we use system-provided
// workqueue - does nothing.
static inline void __fdvio_close_workqueue(
		struct fdvio_dev *const fdvio)
{
#if FDVIO_WQ_MODE_MATCH(PRIVATE)
	destroy_workqueue(fdvio->work_queue);
	fdvio->work_queue = NULL;
#else
	(void)fdvio;
#endif
}

// Helper.
// Wrapper over schedule_work(...) for queue selected by configuration.
static inline void __fdvio_schedule_work(
		struct fdvio_dev *const fdvio
		, struct work_struct *work)
{
#if FDVIO_WQ_MODE_MATCH(SYSTEM)
	(void)fdvio;
	schedule_work(work);
#elif FDVIO_WQ_MODE_MATCH(SYSTEM_HIGHPRI)
	(void)fdvio;
	queue_work(system_highpri_wq, work);
#elif FDVIO_WQ_MODE_MATCH(PRIVATE)
	queue_work(fdvio->work_queue, work);
#else
#error no known Fdvio work queue mode defined
#endif
}

// Helper.
// Wrapper over cancel_work_sync(...) in case we will
// need some custom queue operations on cancelling.
static inline void __fdvio_cancel_work_sync(
		struct fdvio_dev *const fdvio
		, struct work_struct *work)
{
	cancel_work_sync(work);
}

// Work wrapper for recovery sequence
static void __fdvio_recovery_sequence_wrapper(struct work_struct *work)
{
	if (IS_ERR_OR_NULL(work)) {
		pr_err("work ptr is broken: %px\n", work);
		return;
	}

	struct fdvio_dev *fdvio = (struct fdvio_dev *)container_of(
									work, struct fdvio_dev, recover_work);

	// NOTE: this scheduler only invoked on timeout error
	__fdvio_goto_error_and_idle(fdvio, FDVIO_ERROR_OTHER_SIDE_TIMEOUT);
}

// Increment the next xfer ID and return the original value.
// @fdvio {proper ptr to fdvio dev} our device
//
// RETURNS:
// 		the xfer id to assign to the next xfer
// 		0: in case of failure
int __fdvio_set_next_xfer_id(struct fdvio_dev *fdvio)
{
	FDVIO_CHECK_DEVICE(return -1);

	int res = fdvio->next_xfer_id;
	fdvio->next_xfer_id++;
	if (fdvio->next_xfer_id < 0) {
		fdvio->next_xfer_id = 0;
	}
	return res;
}

// Accepts the data given by @xfer as a transfer data (one which will
// next to be sent if client code or other side asks for the xfer).
// Also sets the correct Xfer ID for the xfer.
// NOTE: If next xfer is NULL, then only updates ID.
// NOTE: the xfer will be updated only if new one is good one
// NOTE: if both NULL - just returns.
//
// @fdvio {VALID PTR} the fdvio device to work with.
// @xfer {VALID PTR || NULL} the xfer to accept.
//
// RETURNS:
//      <0: negated error code (if new xfer is bad)
//      >=0: else
int __fdvio_accept_data(struct fdvio_dev* fdvio
		, struct __kernel full_duplex_xfer *xfer)
{
	FDVIO_CHECK_DEVICE(return -ENODEV);

	if (!IS_ERR_OR_NULL(xfer)) {
		if (xfer->size_bytes == 0) {
			fdvio_err("0-sized xfer provided by consumer");
			return -EINVAL;
		}
		if (IS_ERR_OR_NULL(xfer->data_tx)) {
			fdvio_err("broken xfer TX data ptr provided by consumer");
			return -EINVAL;
		}
		fdvio->xfer = xfer;
	}

	if (IS_ERR_OR_NULL(fdvio->xfer)) {
		return 0;
	}

	fdvio->xfer->id = __fdvio_set_next_xfer_id(fdvio);

	// FIXME: workaround for nasty clients who didn't provide RX buffer
	if (fdvio->xfer->data_rx_buf == NULL) {
		if (fdvio->xfer->size_bytes > sizeof(fdvio->own_rx_buf)) {
			fdvio_err("Consumer didn't provide the RX buffer, and xfer"
                      " size is bigger (%zu) than our own RX buf size: "
                      " %zu", fdvio->xfer->size_bytes, sizeof(fdvio->own_rx_buf));
			return -EFAULT;
		}
		fdvio->xfer->data_rx_buf = &fdvio->own_rx_buf[0];
	}

	return 0;
}

/*------------ FDVIO FULL DUPLEX TRANSPORT PLATFORM DEVICE ---------*/

// Inits adapter platform device.
// @pdev the target platform device to work with, if NULL, then the device
//		will be automatically created.
// RETURNS:
//		0: all fine
//		!0: negated error code
static int __fdvio_ff_dev_init(struct fdvio_dev* fdvio
		, struct platform_device *pdev)
{
	fdvio_info("starting initialization of platform adapter device");

	if (IS_ERR_OR_NULL(pdev)) {
		fdvio->pdev = platform_device_register_simple("fdvio_pd", 1, NULL, 0);
	} else {
		fdvio->pdev = pdev;
	}
	if (IS_ERR_OR_NULL(fdvio->pdev)) {
		fdvio_err("could not create/reuse the platform device for fdvio");
		goto pd_register_failed;
	}

	fdvio->fdtd.dev = fdvio;
	fdvio->fdtd.iface = full_duplex_fdvio_iface();
    // Must point to the full duplex device struct
	// in our case the struct is located here: fdvio->fdtd
	dev_set_drvdata(&fdvio->pdev->dev, &fdvio->fdtd);
	
	fdvio_info("full duplex transport device: %px -> dev: %px, if: %px"
               , &fdvio->fdtd, fdvio->fdtd.dev, fdvio->fdtd.iface);
	
	fdvio_info("platform device initialized: %px, fdtd ptr (from drvdata): %px"
               , fdvio->pdev
               , dev_get_drvdata(&fdvio->pdev->dev));

	return 0;

pd_register_failed:
	dev_set_drvdata(&fdvio->pdev->dev, NULL);
	fdvio->fdtd.iface = NULL;
	fdvio->fdtd.dev = NULL;
	return -EFAULT;
}

// Just closes the platform device (adapter toward ICCom).
static int __fdvio_ff_dev_close(struct fdvio_dev* fdvio
		, bool unregister_pd)
{
	fdvio_info("platform adapter device closing: %px", fdvio);

	dev_set_drvdata(&fdvio->pdev->dev, NULL);

	if (unregister_pd) {
		platform_device_unregister(fdvio->pdev);
	}

	fdvio->pdev = NULL;
	fdvio->fdtd.iface = NULL;
	fdvio->fdtd.dev = NULL;

	fdvio_info("platform adapter device closed: %px", fdvio);

	return 0;
}

// Matches the device with "fdvio" driver - used to find the rpmsg
// fdvio device, when we're waiting for it.
static int __fdvio_ff_match_fdvio(struct device *dev, const void *data)
{
    (void)data;
    if (IS_ERR_OR_NULL(dev)) {
        return 0;
    }
    if (IS_ERR_OR_NULL(dev_name(dev))) {
        return 0;
    }
    if (IS_ERR_OR_NULL(dev->driver)) {
        return 0;
    }
    if (IS_ERR_OR_NULL(dev->driver->name)) {
        return 0;
    }
    pr_info("  * rpmsg dev: %s, drv: %s\n", dev_name(dev), dev->driver->name);
    return !strcmp(dev->driver->name, "fdvio");
}

// Device tree node members:
//      None, for now.
//
// Example:
//      iccomsk0: iccomsk0 {
//			compatible = "iccom_socket_if";
//			iccom_dev = <&iccom0>;
//			protocol_family = <22>;
//	    };
//
//	    iccom0: iccom0 {
//			compatible = "iccom";
//			transport_dev = <&fdvio_pd0>;
//	    };
//
//      // will wait for the creation of the rpmsg fdvio device
//      fdvio_pd0: fdvio_pd0 {
//			compatible = "fdvio_pd";
//      };
//
// here we will do real things only when created from DT
static int fdvio_ff_dev_probe(struct platform_device *fdvio_pd)
{
	if (IS_ERR_OR_NULL(fdvio_pd->dev.of_node)) {
		return 0;
	}

	// if we're here, it is creation from Device Tree

    // this section is the full initialization from the device tree,
    // when the fdvio_dev can be created via DT
#ifdef FDVIO_PD_FULL_DT

	dev_info(&fdvio_pd->dev, "Probing the fdvio_pd dev from DT, id: %d"
             , fdvio_pd->id);

	struct device_node *fdvio_pd_dt_node = fdvio_pd->dev.of_node;

	struct device_node *fdvio_dt_node = of_parse_phandle(fdvio_pd_dt_node
								                         , "fdvio_dev", 0);
	if (IS_ERR_OR_NULL(fdvio_dt_node)) {
		dev_err(&fdvio_pd->dev, "\"fdvio_dev\" property is not defined or valid"
                ", you need to set it to bind the fdvio platform device"
                " to its base fdvio device.");
		return -EINVAL;
	}

	// a bit hacky way to get the rpmsg bus device
	struct device *dev = bus_find_device_by_of_node(fdvio_driver.drv.bus
                                                    , fdvio_dt_node);

    if (IS_ERR_OR_NULL(dev)) {
		dev_err(&fdvio_pd->dev, "could not find the 'fdvio_dev' device to"
                ", link with.");
		return -ENODEV;
    }

	dev_info(&fdvio_pd->dev, "fdvio dev to be linked: %px", dev);

	struct fdvio_dev* fdvio = dev_get_drvdata(dev);

	of_node_put(fdvio_dt_node);

	FDVIO_CHECK_DEVICE(return -ENODEV);

	dev_info(&fdvio_pd->dev, "Base fdvio device: %px", fdvio);

	return __fdvio_ff_dev_init(fdvio, fdvio_pd);

#endif

    // this section is for the initialization in the following way:
    // 
    // fdvio_pd -> created via DT
    // * within the creation it waits for the fdvio rpmsg service to come up
    //
    // fdvio -> created via announcement from the other side
    // * checks for the fdvio_pd device in the DT and if it is there
    //   does not create the fdvio_pd device.

	struct device *dev;
   
    if (IS_ERR_OR_NULL(fdvio_driver.drv.bus)) {
        dev_err(&fdvio_pd->dev, "fdvio driver bus is not set!");    
        return -EINVAL;
    }

    for (int i = 0; i < 10; i++) {
	    dev_info(&fdvio_pd->dev, "Search for rpmsg fdvio device:");

        
        dev = bus_find_device(fdvio_driver.drv.bus, NULL, NULL
                              , __fdvio_ff_match_fdvio);

        if (!IS_ERR_OR_NULL(dev)) {
            break;
        }
	    msleep(300);
	    dev_info(&fdvio_pd->dev, "Waiting for the fdvio rpmsg device...");
    }

    if (IS_ERR_OR_NULL(dev)) {
		dev_err(&fdvio_pd->dev, "failed to wait for 'fdvio' rpmsg service"
                " to link with. Aborting.");
		return -ENODEV;
    }

	dev_info(&fdvio_pd->dev, "Detected fdvio rpmsg device:  %s (%px)"
             , dev_name(dev), dev);

	struct fdvio_dev* fdvio = dev_get_drvdata(dev);

	FDVIO_CHECK_DEVICE(return -ENODEV);

	dev_info(&fdvio_pd->dev, "Base fdvio device: %px", fdvio);

	return __fdvio_ff_dev_init(fdvio, fdvio_pd);
}

// Only formal thing.
static int fdvio_ff_dev_remove(struct platform_device *fdvio_pd)
{
	if (IS_ERR_OR_NULL(fdvio_pd->dev.of_node)) {
		return 0;
	}

	// if we're here, we're working with Device Tree

	struct full_duplex_device *fdtd = dev_get_drvdata(&fdvio_pd->dev);

	if (IS_ERR_OR_NULL(fdtd)) {
		dev_err(&fdvio_pd->dev, "The driver data is broken.");
		return -EINVAL;
	}
	
	struct fdvio_dev* fdvio = fdtd->dev;
    FDVIO_CHECK_DEVICE(return -ENODEV);

	return __fdvio_ff_dev_close(fdvio, false);
}

// The ICCom driver compatible definition for
// matching the driver to devices available
//
// @compatible name of compatible driver
struct of_device_id fdvio_pd_driver_id[] = {
	{
		.compatible = "fdvio_pd",
	}
};

// Fdvio platform device driver descriptor.
struct platform_driver fdvio_pd_driver = {
	.probe = fdvio_ff_dev_probe,
	.remove = fdvio_ff_dev_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name = "fdvio_pd",
		.of_match_table = fdvio_pd_driver_id,
		.dev_groups = NULL
	}
};

/*---------------------- FDVIO INIT / CLOSE ------------------------*/

// Short: initializes the fdvio device and prepares it for work.
// But it doesn't start it (cause no default xfer is provided).
// Is to be called by kernel (in probe) when corresponding device is
// detected.
// NOTE: it finishes with device in INITIALIZED state. Then consumer
//    must call the fdvio_start to actually start it.
// @device {valid allocated fdvio_dev ptr}  the already allocated
//    fdvio_dev struct with rpdev ptr set.
//
// THREADING: on the same instance init can be called **only**
//    * if it is a brand newly created instance (no work was done on it yet),
//    * or if this instance was properly closed by __fdvio_close(...) before.
//
// RETURNS:
//      0: all fine
//      !0: negated error code (failure)
int __fdvio_init(void __kernel *device)
{
    CAST_DEVICE_TO_FDVIO;
    FDVIO_CHECK_DEVICE(return -ENODEV);
    FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(fdvio->rpdev, return -ENODEV);

	fdvio_info("starting initialization of device: %px", device);
	if (fdvio->magic == FDVIO_MAGIC) {
		fdvio_warn("Note, the magic already matches.");
	};

	fdvio->magic = FDVIO_MAGIC;
	FDVIO_SWITCH_FORCED(COLD);

	fdvio->xfer = NULL;

	fdvio->next_xfer_id = 1;
	fdvio->delayed_xfer_request = false;

	INIT_WORK(&fdvio->recover_work, __fdvio_recovery_sequence_wrapper);
	int res = __fdvio_init_workqueue(fdvio);
	if (res < 0) {

		fdvio_err("Init abort due to WQ init failure, err: %d", res);
		return res;
	}
	// We create a platform device, which iccom will be bound to.
    // NOTE: this device is just an adapter to provide the iccom
    // formal device to bind to and provide the data.

	// timeout timer
	timer_setup(&fdvio->wait_timeout_timer
			, __fdvio_other_side_wait_timeout_handler, 0);



    // if the fdvio_pd node is declared in the DT, then we will not
    // create it by ourselves - it will be created by kernel automatically
    // and then inside its probe it will wait for 'fdvio' device on rpmsg
    // bus.

    struct device_node * fdvio_pd_node = of_find_compatible_node(
                                                NULL, NULL, "fdvio_pd");
    if (IS_ERR_OR_NULL(fdvio_pd_node)) {
	    fdvio_info("automatic creating fdvio_pd device, cause not in DT.");
	    __fdvio_ff_dev_init(fdvio, NULL);
    } else {
	    fdvio_info("fdvio_pd device is to be provided from DT.");
        of_node_put(fdvio_pd_node);
    }

	if (!FDVIO_SWITCH_STRICT(COLD, INITIALIZED)) {
		BUG_ON(true);
	};

	fdvio_info("fdvio device initialized: %px", device);
	return 0;
}

// API
//
// Closes the device.
// See struct full_duplex_interface description for more info.
// RETURNS:
// 		>=0: all ok even if device is already or closed
// 			or never initialized
// 		<0: negated error code
__maybe_unused
int __fdvio_close(void __kernel *device)
{
    CAST_DEVICE_TO_FDVIO;
    FDVIO_CHECK_DEVICE(return -ENODEV);
    FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(fdvio->rpdev, return -ENODEV);

	fdvio_info("closing dev: %px, dev state: %d", device, FDVIO_STATE());

	__fdvio_ff_dev_close(fdvio, true);

    int res = fdvio_stop(device);
    if (res) {
		fdvio_err("Can't close dev: failed to stop the device,"
                  " error: %d", res);
		return -EFAULT;
    }

	// wrap up with used workqueue
	__fdvio_close_workqueue(fdvio);

    if (!FDVIO_SWITCH_STRICT(INITIALIZED, COLD)
            || !FDVIO_SWITCH_STRICT(COLD, COLD)) {
		fdvio_err("Can't close dev: INITIALIZED -> COLD failed");
		return -EFAULT;
	}

	fdvio->magic = 0;
	fdvio_info("closed dev: %px", device);

	return 0;
}

/*----------- FDVIO FULL DUPLEX INTERFACE DEFINITION ---------------*/

// @device is a pointer to the PLATFORM DEVICE: struct device*
int fdvio_fdif_data_xchange(void __kernel *device
                          , struct __kernel full_duplex_xfer *xfer
                          , bool force_size_change)
{
	FROM_PLATFORM_DEV_TO_FDVIO;
	fdvio_trace("xfer size: %zu, state: %d", xfer ? xfer->size_bytes : 0
                , FDVIO_STATE());
	return fdvio_data_xchange(fdvio, xfer, force_size_change);
}

// @device is a pointer to the PLATFORM DEVICE: struct device*
int fdvio_fdif_default_data_update(void __kernel *device
                                 , struct full_duplex_xfer *xfer
                                 , bool force_size_change)
{
	FROM_PLATFORM_DEV_TO_FDVIO;
	fdvio_trace("xfer size: %zu, state: %d", xfer ? xfer->size_bytes : 0
				, FDVIO_STATE());
	return fdvio_default_data_update(fdvio, xfer, force_size_change);
}

// @device is a pointer to the PLATFORM DEVICE: struct device*
bool fdvio_fdif_is_running(void __kernel *device)
{
	FROM_PLATFORM_DEV_TO_FDVIO;
	return fdvio_is_running(fdvio);
}

// @device is a pointer to the PLATFORM DEVICE: struct device*
int fdvio_fdif_start(void __kernel *device
		, struct full_duplex_xfer *initial_xfer)
{
	FROM_PLATFORM_DEV_TO_FDVIO;
	fdvio_trace("xfer size: %zu, state: %d"
                , initial_xfer ? initial_xfer->size_bytes : 0
				, FDVIO_STATE());
	return fdvio_start(fdvio, initial_xfer);
}

// @device is a pointer to the PLATFORM DEVICE: struct device*
int fdvio_fdif_reset(void __kernel *device
             , struct full_duplex_xfer *initial_xfer)
{
	FROM_PLATFORM_DEV_TO_FDVIO;
	fdvio_trace("xfer size: %zu, state: %d"
                , initial_xfer ? initial_xfer->size_bytes : 0
				, FDVIO_STATE());
	return fdvio_reset(fdvio, initial_xfer);
}

// @device is a pointer to the PLATFORM DEVICE: struct device*
int fdvio_fdif_stop(void __kernel *device)
{
	FROM_PLATFORM_DEV_TO_FDVIO;
	fdvio_trace("stop call, state: %d"
				, FDVIO_STATE());
	return fdvio_stop(fdvio);
}

const struct full_duplex_sym_iface fdvio_duplex_iface = {
	.data_xchange = &fdvio_fdif_data_xchange
	, .default_data_update = &fdvio_fdif_default_data_update
	, .is_running = &fdvio_fdif_is_running
	, .init = &fdvio_fdif_start
	, .reset = &fdvio_fdif_reset
	, .close = &fdvio_fdif_stop
};

// API
//
// Returns ptr to the full duplex device interface object
// which defines fdvio device interface.
//
// RETURNS:
//      valid ptr to struct full_duplex_sym_iface with all
//      fields filled
__maybe_unused
const struct full_duplex_sym_iface *full_duplex_fdvio_iface(void)
{
	return &fdvio_duplex_iface;
}
EXPORT_SYMBOL(full_duplex_fdvio_iface);

/* --------------------- DRIVER PROBING / REMOVAL ---------------------- */

// API
//
// This guy gets called when kernel finds a new device on the rpmsg bus,
// or when our driver has just been plugged in.
// @dev the detected device
//
// NOTE: we don't start the device, we create it, and wait for the consumer
//     code to start us, cause we can not work without consumer.
//
// RETURNS: 
//      0: success
//      !=0: negated error code
__maybe_unused
static int fdvio_probe(struct rpmsg_device *rpdev)
{
	pr_info("fdvio: probing of fdvio device started, rpdev: %px\n", rpdev);

	if (IS_ERR_OR_NULL(rpdev)) {
		pr_err("Broken pointer to the rpmsg_device in %s\n", __func__);
		return -ENODEV;
	}
	if (IS_ERR_OR_NULL(rpdev->ept)) {
		pr_err("Broken pointer to the rpmsg_device->ept in %s\n", __func__);
		return -EINVAL;
	}

    // we want to announce our announcement to the other side
    rpdev->announce = true;

	dev_info(&rpdev->dev, "fdvio: driver rev.: "BOSCH_FDVIO_DRIVER_VERSION"\n");
	dev_info(&rpdev->dev, "fdvio: new device, channel: 0x%x -> 0x%x\n"
			 , rpdev->src, rpdev->dst);

	struct fdvio_dev *fdvio = (struct fdvio_dev *)kmalloc(
									sizeof(struct fdvio_dev), GFP_KERNEL);
	int res = 0;
	if (IS_ERR_OR_NULL(fdvio)) {
		dev_err(&rpdev->dev, "fdvio: failed to allocate memory for fdvio_dev.\n");
		res = -ENOMEM;
		goto fdvio_alloc_failed;
	}

	dev_set_drvdata(&rpdev->dev, fdvio);
	fdvio->rpdev = rpdev;

	res = __fdvio_init(fdvio);
	fdvio_info("Fdvio device created: %px", fdvio);
	if (res) {
		dev_err(&rpdev->dev, "fdvio: initialization failed: errno: %d\n", res);
		goto fdvio_init_failed;
	}

	// NOTE: after return we might immediately get the messages from the
	//    other side, which will be effectively dropped until the client
	//    driver gets bound to us.
	return 0;

fdvio_init_failed:
	dev_set_drvdata(&rpdev->dev, NULL);
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
static void fdvio_remove(struct rpmsg_device *rpdev)
{
	dev_info(&rpdev->dev, "fdvio: removing device, channel: 0x%x -> 0x%x\n"
			 , rpdev->src, rpdev->dst);

	int res = 0;
	struct fdvio_dev *fdvio = (struct fdvio_dev *)dev_get_drvdata(&rpdev->dev);

	if (IS_ERR_OR_NULL(fdvio)) {
		dev_err(&rpdev->dev, "fdvio: rpdev has no valid ptr do fdvio dev."
						" It will not be a graceful close.\n");
		res = -ENODEV;
	} else {
		res = __fdvio_close(fdvio);

		if (res) {
			dev_err(&rpdev->dev, "fdvio: __fdvio_close failed, errno: %d\n", res);
		}
	}

	dev_set_drvdata(&rpdev->dev, NULL);
	kfree(fdvio);

	dev_err(&rpdev->dev, "fdvio: closed (old ptr: %px) with result: %d\n"
			, fdvio, res);
}

// NOTE: the other side announces the available channels, using the
//  names as identifiers, and those names are matched via the names
//  in this table.
// NOTE: after the match in this table is found the channel is created,
//  with proper endpoint and the corresponding (in our case our) driver
//  is probed.
//
//  The list of compatible RPMSG channels (by their names, which also
//  used on the other side to announce them):
static struct rpmsg_device_id fdvio_id_table[] = {
	{ .name = "fdvio"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
        , .driver_data = 0
#endif
    }
	, { }
};
MODULE_DEVICE_TABLE(rpmsg, fdvio_id_table);


// Registering the driver as rpmsg driver
static struct rpmsg_driver fdvio_driver = {
	.drv.name       = "fdvio",
	.id_table       = fdvio_id_table,
	.probe          = fdvio_probe,
	.callback       = __fdvio_rpmsg_rcv_cb,
	.remove         = fdvio_remove,
};

/* --------------------- MODULE HOUSEKEEPING SECTION ------------------- */

static int __init fdvio_module_init(void)
{
	pr_info("loading fdvio module...");

	int ret = register_rpmsg_driver(&fdvio_driver);
	if (ret != 0) {
		pr_err("fdvio main driver register failed: %d", ret);
		return ret;
	}
	pr_info("registered rpmsg driver.");
	
	ret = platform_driver_register(&fdvio_pd_driver);
	if (ret != 0) {
		pr_err("fdvio platform driver register failed: %d", ret);
		goto platform_drv_failed;
	}
	pr_info("registered platform driver.");

	pr_info("fdvio module loaded.");

	return 0;

platform_drv_failed:
	unregister_rpmsg_driver(&fdvio_driver);
	return ret;
}

static void __exit fdvio_module_exit(void)
{
	pr_info("unloading fdvio module...");

	platform_driver_unregister(&fdvio_pd_driver);
	unregister_rpmsg_driver(&fdvio_driver);

	pr_info("sucessfully unloaded fdvio module.");
}

module_init(fdvio_module_init);
module_exit(fdvio_module_exit);

MODULE_DESCRIPTION("Full duplex VirtIO (rpmsg-based) device");
MODULE_AUTHOR("Artem Gulyaev <Artem.Gulyaev@bosch.com>");
MODULE_LICENSE("GPL v2");

