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
#include <linux/delay.h>
#include <linux/rpmsg.h>

#include <linux/full_duplex_interface.h>


/* --------------------- UTILITIES SECTION ----------------------------- */


#define FDVIO_LOG_PREFIX "fdvio: "


#define fdvio_emerg(fmt, ...)                                               \
    dev_emerg(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_crit(dev, fmt, ...)                                           \
    dev_crit(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_alert(dev, fmt, ...)                                          \
    dev_alert(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_err(dev, fmt, ...)                                            \
    dev_err(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_warn(dev, fmt, ...)                                           \
    dev_warn(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_notice(dev, fmt, ...)                                         \
    dev_notice(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_info(dev, fmt, ...)                                           \
    dev_info(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)


#define fdvio_emerg_rlim(fmt, ...)                                               \
    dev_emerg_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_crit_rlim(dev, fmt, ...)                                           \
    dev_crit_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_alert_rlim(dev, fmt, ...)                                          \
    dev_alert_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_err_rlim(dev, fmt, ...)                                            \
    dev_err_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_warn_rlim(dev, fmt, ...)                                           \
    dev_warn_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_notice_rlim(dev, fmt, ...)                                         \
    dev_notice_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)
#define fdvio_info_rlim(dev, fmt, ...)                                           \
    dev_info_ratelimited(fdvio->rpdev, FDVIO_LOG_PREFIX"%s: at %d line: "fmt"\n"
              , __func__, __LINE__, ##__VA_ARGS__)


#define CAST_DEVICE_TO_FDVIO                                        \
        struct fdvio_dev *fdvio = (struct fdvio_dev *fdvio)device;
#define FDVIO_CHECK_DEVICE(error_action)                    \
	if (IS_ERR_OR_NULL(fdvio)) {                            \
		fdvio_err("%s: no device;\n", __func__);            \
		error_action;                                       \
	}
#define FDVIO_CHECK_KERNEL_DEVICE(error_action)             \
	if (IS_ERR_OR_NULL(fdvio->rpdev)) {                     \
		fdvio_err("%s: no kernel device;\n", __func__);     \
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

#define FDVIO_SWITCH_STRICT(from, to)                          \
	(atomic_cmpxchg(&fdvio->state,                             \
					FDVIO_STATE_##to,                          \
					FDVIO_STATE_##from) != FDVIO_STATE_##to)
#define FDVIO_SWITCH_FORCED(to)                          \
	atomic_set(&fdvio->state, FDVIO_STATE_##to)
#define FDVIO_STATE(state)                          \
	(&fdvio->state == FDVIO_STATE_##state)

#ifdef FDVIO_DEBUG
#define FDVIO_ASSERT_STATE(state)                                          \
	if (&fdvio->state != FDVIO_STATE_##state) {                            \
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
#define FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC 20


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
// NOTE: right before we enter the IDLE state all xfer flags must be dropped 
//     like "got other side data" and "sent our data" flags.
#define FDVIO_STATE_IDLE 3
// The state in which we push the outgoing data:
// * send out our data and
// * start the timeout timer
// * then switch to the XFER_RX state
//
// we switch to this state by
// * fdvio_rpmsg_rcv_cb callback from the other side.
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
struct {
	uint32_t magic;
	atomic_t state; 
	struct rpmsg_device *rpdev;
	
	// never owns the data
	struct full_duplex_xfer *xfer;

	int next_xfer_id;

	bool delayed_xfer_request;

	struct timer_list wait_timeout_timer;
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
//
// LOCKING: doesn't lock the data, it is up to the caller to
//     ensure that there is no data races.
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

/*---------------------- FDVIO DEVICE API ----------------------------*/

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END
// In short: this function is called by consumer driver to trigger the
// xfer.
// NOTE: in comparison to SymSPI we will not copy the xfer, but actually
//     use one which is provided (expectation is that consumer will not
//     operate the xfer data until the xfer result is available, or to update
//     the xfer the separate xfer will be created and pointed to by @xfer
//     here)
// See the Full Duplex xfer interface for full description.
//
// STATUS:
//     * IDLE->XFER
// @@@@@@@@@@@@@@@@@@@@@@@@@@-----2023-06-----@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN
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
// @@@@@@@@@@@@@@@@@@@@@@@@@@-----2023-06-----@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END

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
		, struct full_duplex_xfer *initial_xfer)
{
    CAST_DEVICE_TO_FDVIO;
    FDVIO_CHECK_DEVICE(return -ENODEV);
    FDVIO_CHECK_KERNEL_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(initial_xfer, return -EINVAL);

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
	fdvio->delayed_xfer_request = false;

	// timeout timer
	timer_setup(&fdvio->wait_timeout_timer,
			__fdvio_other_side_wait_timeout, 0);

	int res = __fdvio_accept_data(fdvio, initial_xfer);
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
             , struct full_duplex_xfer *initial_xfer)
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







































/*---------------------- STATE SWITCHING ROUTINES --------------------*/

// Returns us to IDLE state.
void __fdvio_back_to_idle(struct fdvio_dev *fdvio)
{
	FDVIO_ASSERT_DEVICE();

}

// @@@@@@@@@@@@@@@@@@@@@@@@@@-----2023-06-----@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN
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
		return -FDVIO_ERROR_NO_SWITCH;
	}

	if (xfer != NULL) {
		fdvio->xfer = xfer;
	}

	fdvio->delayed_xfer_request = false;

	int res = rpmsg_sendto(fdvio->rpdev->ept, fdvio->xfer.data_tx
				, fdvio->xfer.size_bytes
				, fdvio->rpdev->dst);
	if (res != 0) {
		fdvio_err("The rpmsg_send 0x%x -> 0x%x, data size %d failed with"
					" code: %d", fdvio->rpdev->src, fdvio->rpdev->dst
					, fdvio->xfer.size_bytes, res);
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
// @@@@@@@@@@@@@@@@@@@@@@@@@@-----2023-06-----@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END

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
void __fdvio_goto_error_and_idle(struct fdvio_dev *fdvio
		, int error_code)
{
	// @@##@@##
}


/*-------------------------- TIMERS BLOCK ----------------------------*/

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

// Launches error recovery on timeout
static void __fdvio_other_side_wait_timeout(struct timer_list *t)
{
	struct fdvio_dev *fdvio = from_timer(fdvio, t, wait_timeout_timer);

	FDVIO_CHECK_DEVICE(return);
	FDVIO_CHECK_KERNEL_DEVICE(return);

	__fdvio_goto_error_and_idle(fdvio, FDVIO_ERROR_OTHER_SIDE_TIMEOUT);
}

/*-------------------------- TIMERS BLOCK END ------------------------*/












// @@@@@@@@@@@@@@@@@@@@@@@@@@-----2023-06-----@@@@@@@@@@@@@@@@@@@@@@@@@@@ V BEGIN

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
int fdvio_rpmsg_rcv_cb(struct rpmsg_device *rpdev, void *msg, int msg_len
				, void *private_data, u32 source)
{
	if (IS_ERR_OR_NULL(rpdev)) {
		pr_err("Broken ptr: rpmsg_device in "__func__"\n");
		return -ENODEV;
	}
	if (IS_ERR_OR_NULL(rpdev->dev)) {
		pr_err("Broken ptr: rpmsg_device->dev in "__func__"\n");
		return -ENODEV;
	}

	struct fdvio_dev *fdvio = (struct fdvio_dev *)dev_get_drvdata(rpdev->dev);

	FDVIO_CHECK_DEVICE(return -ENODEV);
	FDVIO_CHECK_PTR(msg, return -EINVAL);
	FDVIO_CHECK_PTR(rpdev->ept, return -EINVAL);

	// trying to initialize the new xfer, send out our data and start timer.
	int res = __fdvio_goto_xfer(fdvio, NULL);

	if (res != 0 && res != -FDVIO_ERROR_NO_SWITCH) {
		// NOTE: no error recovery here, cause it will be done by
		// 		the __fdvio_goto_xfer routine internally
		return 0;
	}

	// RX sequence here

	// wait for the XFER_RX state, which indicates
	// that TX part of the sequence is done
	while (true) {
		if (FDVIO_STATE(XFER_TX)) {
			break;
		}
		// the state drifted away, say due to error, or timeout
		if (&fdvio->state != FDVIO_STATE_XFER_TX
				&& &fdvio->state != FDVIO_STATE_XFER_RX) {
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

	if (fdvio->xfer.size_bytes != msg_len) {
		__fdvio_goto_error_and_idle(fdvio, FDVIO_ERROR_XFER_SIZE_MISMATCH);
		return 0;
	}

	struct full_duplex_xfer *next_xfer = NULL;
	bool start_immediately = false;

	// NOTE: the xfer DOES NOT own the data
	fdvio->xfer.data_rx_buf = msg;
	if (!IS_ERR_OR_NULL(fdvio->xfer.done_callback)) {
		next_xfer = fdvio->xfer.done_callback(
                        &fdvio->xfer
                        , fdvio->next_xfer_id
                        , &start_immediately
                        , fdvio->xfer->consumer_data);
	}
	// we must drop it instantly, as long as we don't own the data
	// and client code already processed it
	fdvio->xfer.data_rx_buf = NULL;
	
	if (IS_ERR(next_xfer)) {
		fdvio_info("Device is halted by consumer request.");
		return;
	}

	res = __fdvio_accept_data(fdvio, new_xfer);
	if (res != 0) {
		fdvio_err("new xfer could not be accepted, retaining original one");
		// NOTE: nothing really to do here, we just keep the original xfer.
	}
	
	FDVIO_SWITCH_STRICT(XFER_RX, IDLE);

	// NOTE: this will not recurse, cause when reached the TX state
	// 	it will send our data, start timer and return.
	if (start_immediately || fdvio->delayed_xfer_request) {
		fdvio_data_xchange(fdvio, NULL, false);
	}

	return 0;
}

/*------------------------------ FDVIO DEVICE ------------------------------*/


// Increment the next xfer ID and return the original value.
// @fdvio {proper ptr to fdvio dev} our device
//
// RETURNS:
// 		the xfer id to assign to the next xfer
// 		0: in case of failure
int fdvio_set_next_xfer_id(struct fdvio_dev *fdvio)
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
//
// @fdvio {VALID PTR} the fdvio device to work with.
// @xfer {VALID PTR || NULL} the xfer to accept.
//
// RETURNS:
//      >=0: all fine, the id of the xfer to happen
//      <0: negated error code
int __fdvio_accept_data(struct fdvio_dev* fdvio
		, struct __kernel full_duplex_xfer *xfer)
{
	FDVIO_CHECK_DEVICE(return -ENODEV);

	if (!IS_ERR_OR_NULL(xfer)) {
		if (xfer->size_bytes == 0) {
			fdvio_error("0-sized xfer provided by consumer");
			return -EINVAL;
		}
		if (IS_ERR_OR_NULL(xfer->data_tx)) {
			fdvio_error("broken xfer TX data ptr provided by consumer");
			return -EINVAL;
		}
		fdvio->xfer = xfer;
		return;
	}

	fdvio->xfer.id = fdvio_set_next_xfer_id(fdvio);

	return fdvio->xfer.id;
}
// @@@@@@@@@@@@@@@@@@@@@@@@@@-----2023-06-----@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ V END


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
	fdvio->rpdev = rpdev;

	res = fdvio_init(fdvio, NULL);
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
