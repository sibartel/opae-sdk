// Copyright(c) 2017-2021, Intel Corporation
//
// Redistribution  and  use  in source  and  binary  forms,  with  or  without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of  source code  must retain the  above copyright notice,
//   this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// * Neither the name  of Intel Corporation  nor the names of its contributors
//   may be used to  endorse or promote  products derived  from this  software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,  BUT NOT LIMITED TO,  THE
// IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT  SHALL THE COPYRIGHT OWNER  OR CONTRIBUTORS BE
// LIABLE  FOR  ANY  DIRECT,  INDIRECT,  INCIDENTAL,  SPECIAL,  EXEMPLARY,  OR
// CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT LIMITED  TO,  PROCUREMENT  OF
// SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE,  DATA, OR PROFITS;  OR BUSINESS
// INTERRUPTION)  HOWEVER CAUSED  AND ON ANY THEORY  OF LIABILITY,  WHETHER IN
// CONTRACT,  STRICT LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE  OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,  EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H

#include <opae/fpga.h>

extern "C" {
fpga_result send_fme_event_request(fpga_handle, fpga_event_handle, int);
fpga_result send_port_event_request(fpga_handle, fpga_event_handle, int);
fpga_result send_uafu_event_request(fpga_handle, fpga_event_handle, uint32_t, int);
fpga_result check_err_interrupts_supported(fpga_handle, fpga_objtype*);
fpga_result driver_register_event(fpga_handle, fpga_event_type, fpga_event_handle, uint32_t);
fpga_result driver_unregister_event(fpga_handle, fpga_event_type, fpga_event_handle);
int xfpga_plugin_initialize(void);
int xfpga_plugin_finalize(void);
}

#include "intel-fpga.h"
#include <stdlib.h>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <string>
#include <cstring>
#include "types_int.h"
#include "gtest/gtest.h"
#include "mock/test_system.h"
#include "mock/fpgad_control.h"
#include "fpga-dfl.h"
#include "error_int.h"
#include "xfpga.h"
#include <opae/enum.h>
#include <opae/properties.h>
#include <opae/access.h>
#include <linux/ioctl.h>
#include <poll.h>
#include <dlfcn.h>

using namespace opae::testing;

static std::string sysfs_fme = "/sys/class/fpga_region/region0/dfl-fme.0";
static std::string dev_fme = "/dev/dfl-fme.0";
static std::string sysfs_port = "/sys/class/fpga/fpga_region/region0/dfl-fme.0";
static std::string dev_port = "/dev/dfl-port.0";
static bool gEnableIRQ = false;

static void get_path(const std::string object_type, fpga_handle handle){
  auto h = (struct _fpga_handle*)handle; 
  auto tok = (struct _fpga_token*)h->token; 
  if (object_type.compare("fme") == 0)
  {
     sysfs_fme = tok->sysfspath;
     dev_fme = tok->devpath;
  }   
  else if (object_type.compare("port") == 0)
  {
     sysfs_port = tok->sysfspath;
     dev_port = tok->devpath;
  }
}

int dfl_get_fme_err_irq(mock_object * m, int request, va_list argp) {
	int retval = -1;
	errno = EINVAL;
	UNUSED_PARAM(m);
	UNUSED_PARAM(request);
	UNUSED_PARAM(argp);
	uint32_t *num_irqs = va_arg(argp, uint32_t *);

	if (gEnableIRQ) {
		*num_irqs = 1;
		retval = 0;
		errno = 0;
	} else {
		*num_irqs = 0;

		retval = -1;
		errno = ENOTSUP;
	}



	va_end(argp);
	return retval;
}

int dfl_get_port_err_irq(mock_object * m, int request, va_list argp) {
	int retval = -1;
	errno = EINVAL;
	UNUSED_PARAM(m);
	UNUSED_PARAM(request);

	uint32_t *num_irqs = va_arg(argp, uint32_t *);

	if (gEnableIRQ) {
		*num_irqs = 1;
		retval = 0;
		errno = 0;
	}
	else {
		*num_irqs = 0;
		retval = -1;
		errno = ENOTSUP;
	}

	va_end(argp);
	return retval;
}

int dfl_get_port_uint_irq(mock_object * m, int request, va_list argp) {
	int retval = -1;
	errno = EINVAL;
	UNUSED_PARAM(m);
	UNUSED_PARAM(request);

	uint32_t *num_irqs = va_arg(argp, uint32_t *);
	if (gEnableIRQ) {
		*num_irqs = 4;
		retval = 0;
		errno = 0;
	}
	else {
		*num_irqs = 0;
		retval = -1;
		errno = ENOTSUP;
	}
	va_end(argp);
	return retval;
}

int set_dummy_dfl_irq(mock_object * m, int request, va_list argp) {

	int retval = -1;
	errno = EINVAL;
	UNUSED_PARAM(m);
	UNUSED_PARAM(request);
	struct dfl_fpga_irq_set *irq = va_arg(argp, struct dfl_fpga_irq_set *);

	if (!irq) {
		OPAE_MSG("fme_irq is NULL");
		goto out_EINVAL;
	}
	if (irq->count <= 0) {
		OPAE_MSG("wrong structure size");
		goto out_EINVAL;
	}

		retval = -1;
		errno = EINVAL;

out:
  va_end(argp);
  return retval;

out_EINVAL:
  retval = -1;
  errno = EINVAL;
  goto out;
}


int set_dfl_irq(mock_object * m, int request, va_list argp) {

	int retval = -1;
	errno = EINVAL;
	UNUSED_PARAM(m);
	UNUSED_PARAM(request);

	struct dfl_fpga_irq_set *irq = va_arg(argp, struct dfl_fpga_irq_set *);
	if (!irq) {
		OPAE_MSG("fme_irq is NULL");
		goto out_EINVAL;
	}
	if (irq->count <= 0 ) {
		OPAE_MSG("wrong structure size");
		goto out_EINVAL;
	}
	if (gEnableIRQ) {
		uint32_t i;
		uint64_t data = 1;
		// Write to each eventfd to signal one IRQ event.
		for (i = 0; i < irq->count; ++i) {
			if (irq->evtfds[i] >= 0)
				if (write(irq->evtfds[i], &data, sizeof(data)) !=
					sizeof(data)) {
					OPAE_ERR("IRQ write < 8 bytes");
				}
		}
	}
	retval = 0;
	errno = 0;
out:
	va_end(argp);
	return retval;

out_EINVAL:
	retval = -1;
	errno = EINVAL;
	goto out;
}


class events_p : public ::testing::TestWithParam<std::string>,
                 public fpgad_control {
 protected:
  events_p()
      : tokens_dev_{{nullptr, nullptr}},
        tokens_accel_{{nullptr, nullptr}},
        handle_dev_(nullptr),
        handle_accel_(nullptr) {}

  virtual void SetUp() override {
    std::string platform_key = GetParam();
    ASSERT_TRUE(test_platform::exists(platform_key));
    platform_ = test_platform::get(platform_key);
    system_ = test_system::instance();
    system_->initialize();
    system_->prepare_syfs(platform_);

    ASSERT_EQ(FPGA_OK, xfpga_plugin_initialize());

    ASSERT_EQ(xfpga_fpgaGetProperties(nullptr, &filter_dev_), FPGA_OK);
    ASSERT_EQ(fpgaPropertiesSetDeviceID(filter_dev_, 
                                        platform_.devices[0].device_id), FPGA_OK);
    ASSERT_EQ(fpgaPropertiesSetObjectType(filter_dev_, FPGA_DEVICE), FPGA_OK);
    ASSERT_EQ(xfpga_fpgaEnumerate(&filter_dev_, 1, tokens_dev_.data(), tokens_dev_.size(),
                            &num_matches_dev_), FPGA_OK);
    ASSERT_GT(num_matches_dev_, 0);

    ASSERT_EQ(xfpga_fpgaGetProperties(nullptr, &filter_accel_), FPGA_OK);
    ASSERT_EQ(fpgaPropertiesSetDeviceID(filter_accel_, 
                                        platform_.devices[0].device_id), FPGA_OK);
    ASSERT_EQ(fpgaPropertiesSetObjectType(filter_accel_, FPGA_ACCELERATOR), FPGA_OK);
    ASSERT_EQ(xfpga_fpgaEnumerate(&filter_accel_, 1, tokens_accel_.data(),
                            tokens_accel_.size(), &num_matches_), FPGA_OK);
    ASSERT_GT(num_matches_, 0);
    ASSERT_EQ(xfpga_fpgaOpen(tokens_dev_[0], &handle_dev_, 0), FPGA_OK);
    ASSERT_EQ(xfpga_fpgaOpen(tokens_accel_[0], &handle_accel_, 0), FPGA_OK);

    get_path("fme", handle_dev_);
    get_path("port", handle_accel_);

    ASSERT_EQ(xfpga_fpgaCreateEventHandle(&eh_), FPGA_OK);

    fpgad_start();

    uint32_t i;
    for (i = 0 ; i < num_matches_dev_ ; ++i) {
      fpgad_watch(tokens_dev_[i]);
    }
    for (i = 0 ; i < num_matches_ ; ++i) {
      fpgad_watch(tokens_accel_[i]);
    }
  }

  virtual void TearDown() override {
    fpgad_stop();

    EXPECT_EQ(xfpga_fpgaDestroyEventHandle(&eh_), FPGA_OK);

    EXPECT_EQ(fpgaDestroyProperties(&filter_dev_), FPGA_OK);
    EXPECT_EQ(fpgaDestroyProperties(&filter_accel_), FPGA_OK);

    if (handle_dev_) { 
        EXPECT_EQ(xfpga_fpgaClose(handle_dev_), FPGA_OK); 
        handle_dev_ = nullptr;
    }

    if (handle_accel_) { 
        EXPECT_EQ(xfpga_fpgaClose(handle_accel_), FPGA_OK); 
        handle_accel_ = nullptr;
    }
 
    for (auto &t : tokens_dev_) {
      if (t) {
        EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyToken(&t));
        t = nullptr;
      }
    }

    for (auto &t : tokens_accel_) {
      if (t) {
        EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyToken(&t));
        t = nullptr;
      }
    }
    xfpga_plugin_finalize();
    system_->finalize();
  }

  fpga_properties filter_dev_;
  fpga_properties filter_accel_;
  std::array<fpga_token, 2> tokens_dev_;
  std::array<fpga_token, 2> tokens_accel_;
  fpga_handle handle_dev_;
  fpga_handle handle_accel_;
  uint32_t num_matches_dev_;
  uint32_t num_matches_;
  test_platform platform_;
  test_system *system_;
  fpga_event_handle eh_;
};

/*
 * @test       event_01
 *
 * @brief      When the fpga_event_handle pointer to
 *             fpgaCreateEventHandle() is NULL, the function returns
 *             FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_01) {
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaCreateEventHandle(NULL));
}

/**
 * @test       event_02
 *
 * @brief      When the fpga_event_handle pointer to
 *             fpgaDestroyEventHandle() is NULL, the function returns
 *             FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_02) {
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaDestroyEventHandle(NULL));
}

/**
 * @test       event_03
 *
 * @brief      Tests fpgaRegisterEvent()'s ability to detect invalid
 *             arguments. When the handle is NULL or otherwise invalid,
 *             FPGA_INVALID_PARAM. When the handle has an invalid token,
 *             FPGA_INVALID_PARAM. When the handle's token describes a
 *             device for which the given event does't apply,
 *             FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_03) {
  fpga_event_type e = FPGA_EVENT_ERROR;
  fpga_event_handle eh;

  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&eh));

  // NULL handle.
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(NULL, e, eh, 0));

  // handle with bad magic.
  struct _fpga_handle _h;
  struct _fpga_token _t;

  // token setup
  strncpy(_t.sysfspath, sysfs_port.c_str(), sysfs_port.size() + 1);
  strncpy(_t.devpath, dev_port.c_str(), dev_port.size() + 1);
  _t.hdr.magic = FPGA_TOKEN_MAGIC;
  _t.errors = nullptr;
  std::string errpath = sysfs_port + "/errors";
  build_error_list(errpath.c_str(), &_t.errors);

  memset(&_h, 0, sizeof(_h));
  _h.token = &_t;
  _h.magic = FPGA_INVALID_MAGIC;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(&_h, e, eh, 0));

  // handle with bad token.
  _t.hdr.magic = FPGA_INVALID_MAGIC;
  _h.magic = FPGA_HANDLE_MAGIC;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(&_h, e, eh, 0));

  // token/event mismatch.
  strncpy(_t.sysfspath, sysfs_fme.c_str(), sysfs_fme.size() + 1);
  strncpy(_t.devpath, dev_fme.c_str(), dev_fme.size() + 1);
  _t.hdr.magic = FPGA_TOKEN_MAGIC;
  _t.errors = nullptr;
  errpath = sysfs_fme + "/errors";
  build_error_list(errpath.c_str(), &_t.errors);

  EXPECT_EQ(FPGA_INVALID_PARAM,
            xfpga_fpgaRegisterEvent(&_h, FPGA_EVENT_INTERRUPT, eh, 0));

  EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyEventHandle(&eh));
}

/**
 * @test       event_04
 *
 * @brief      Tests fpgaUnregisterEvent()'s ability to detect invalid
 *             arguments. When the handle is NULL or otherwise invalid,
 *             FPGA_INVALID_PARAM. When the handle has an invalid token,
 *             FPGA_INVALID_PARAM. When the handle's token describes a
 *             device for which the given event does't apply,
 *             FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_04) {
  fpga_event_type e = FPGA_EVENT_ERROR;
  fpga_event_handle eh;

  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&eh));

  // NULL handle.
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(NULL, e, eh));

  // handle with bad magic.
  struct _fpga_handle _h;
  struct _fpga_token _t;

  // token setup
  strncpy(_t.sysfspath, sysfs_port.c_str(), sysfs_port.size() + 1);
  strncpy(_t.devpath, dev_port.c_str(), dev_port.size() + 1);
  _t.hdr.magic = FPGA_TOKEN_MAGIC;
  _t.errors = nullptr;
  std::string errpath = sysfs_port + "/errors";
  build_error_list(errpath.c_str(), &_t.errors);

  memset(&_h, 0, sizeof(_h));
  _h.token = &_t;
  _h.magic = FPGA_INVALID_MAGIC;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(&_h, e, eh));

  // handle with bad token.
  _t.hdr.magic = FPGA_INVALID_MAGIC;
  _h.magic = FPGA_HANDLE_MAGIC;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(&_h, e, eh));

  // token/event mismatch.
  strncpy(_t.sysfspath, sysfs_fme.c_str(), sysfs_fme.size() + 1);
  strncpy(_t.devpath, dev_fme.c_str(), dev_fme.size() + 1);
  _t.hdr.magic = FPGA_TOKEN_MAGIC;
  _t.errors = nullptr;
  errpath = sysfs_fme + "/errors";
  build_error_list(errpath.c_str(), &_t.errors);

  EXPECT_EQ(FPGA_INVALID_PARAM,
            xfpga_fpgaUnregisterEvent(&_h, FPGA_EVENT_INTERRUPT, eh));

  EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyEventHandle(&eh));
}

/**
 * @test       event_drv_08
 *
 * @brief      When passed an event handle with an invalid magic
 *             fpgaDestroyEventHandle() returns FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_drv_08) {
  fpga_event_handle bad_handle;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));
  struct _fpga_event_handle *h = (struct _fpga_event_handle *) bad_handle;

  // Invalid Event Handle magic
  h->magic=0x0;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaDestroyEventHandle(&bad_handle));

  // reset event handle magic and destroy
  h->magic=FPGA_EVENT_HANDLE_MAGIC;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyEventHandle(&bad_handle));
}

/**
 * @test       event_drv_09
 *
 * @brief      When passed an event handle with an invalid fd
 *             fpgaDestroyEventHandle() returns FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_drv_09) {
  fpga_event_handle bad_handle;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));
  struct _fpga_event_handle *h = (struct _fpga_event_handle *) bad_handle;

  // Invalid fd
  auto fddev = h->fd;
  h->fd = -1;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaDestroyEventHandle(&bad_handle));

  // Reset fd to destroy event handle
  h->fd = fddev;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyEventHandle(&bad_handle));
}

/**
 * @test       event_drv_10
 *
 * @brief      When passed an event handle with an invalid magic
 *             fpgaGetOSObjectFromEventHandle() returns FPGA_INVALID_PARAM.
 *
 */
TEST(events, event_drv_10) {
  fpga_event_handle bad_handle;
  int fd;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));
  struct _fpga_event_handle *h = (struct _fpga_event_handle *) bad_handle;

  // Invalid event handle magic
  h->magic=0x0;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaGetOSObjectFromEventHandle(bad_handle, &fd));

  // Reset event handle magic
  h->magic=FPGA_EVENT_HANDLE_MAGIC;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaGetOSObjectFromEventHandle(bad_handle, &fd));
  EXPECT_EQ(FPGA_OK, xfpga_fpgaDestroyEventHandle(&bad_handle));
}

/**
 * @test       register_event
 *
 * @brief      When a valid fpga_event_handle and event types
 *             are passed to fpgaRegisterEvent and fpgaUnregisterEvent.
 *             both API calls return FPGA_OK.
 */
TEST_P(events_p, register_event) {
  fpga_result res;
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
 
  ASSERT_EQ(res = xfpga_fpgaRegisterEvent(handle_dev_, FPGA_EVENT_ERROR, eh_, 0), FPGA_OK)
      << "\tEVENT TYPE: ERROR, RESULT: " << fpgaErrStr(res);
  EXPECT_EQ(res = xfpga_fpgaUnregisterEvent(handle_dev_, FPGA_EVENT_ERROR, eh_), FPGA_OK)
      << "\tRESULT: " << fpgaErrStr(res);
}

/**
 * @test       event_drv_11
 *
 * @brief      When passed an event handle with an invalid magic
 *             xfpga_fpgaUnregisterEvent() returns FPGA_INVALID_PARAM.
 *
 */
TEST_P(events_p, event_drv_11) {
  fpga_event_handle bad_handle = nullptr;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));
  struct _fpga_event_handle *h = (struct _fpga_event_handle *) bad_handle;
  // Invalid event handle magic
  auto valid_magic = h->magic;
  h->magic = 0x0;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT, bad_handle));

  h->magic = valid_magic;
  EXPECT_EQ(xfpga_fpgaDestroyEventHandle(&bad_handle), FPGA_OK);
}

/**
 * @test       event_drv_12
 *
 * @brief      When passed an event handle with an invalid magic
 *             xfpga_fpgaRegisterEvent() returns FPGA_INVALID_PARAM.
 *
 */
TEST_P(events_p, event_drv_12) {
  fpga_event_handle bad_handle = nullptr;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));
  struct _fpga_event_handle *h = (struct _fpga_event_handle *) bad_handle;

  auto valid_magic = h->magic;
  // Invalid event handle magic
  h->magic = 0x0;
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT, bad_handle, 0));
  h->magic = valid_magic;
  EXPECT_EQ(xfpga_fpgaDestroyEventHandle(&bad_handle), FPGA_OK);
}

/**
 * @test       create_destory_invalid
 * @brief      Given a malloc failure, fpgaCreateEventHandle returns 
 *             FPGA_NO_MEMORY.
 */
TEST_P(events_p, create_destroy_invalid) {
  // fail malloc to check edge case
  EXPECT_EQ(xfpga_fpgaDestroyEventHandle(&eh_), FPGA_OK);
  test_system::instance()->invalidate_malloc();

  auto res = xfpga_fpgaCreateEventHandle(&eh_);
  EXPECT_EQ(FPGA_NO_MEMORY,res);
  ASSERT_EQ(xfpga_fpgaCreateEventHandle(&eh_), FPGA_OK);
}

/**
 * @test       irq_event_04
 *
 * @brief      Given a driver with IRQ support<br>
 *             when fpgaRegisterEvent is called with<br>
 *             an invalid handle<br>
 *             then the call fails with FPGA_INVALID_PARAM.<br>
 *             Repeat for fpgaUnregisterEvent.<br>
 *
 */
TEST_P(events_p, irq_event_04) {
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(NULL, FPGA_EVENT_INTERRUPT,
                                       eh_, 0));
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(NULL, FPGA_EVENT_INTERRUPT,
                                       eh_));
}

/**
 * @test       irq_event_05
 *
 * @brief      Given a driver with IRQ support<br>
 *             when fpgaRegisterEvent is called with<br>
 *             an invalid event handle<br>
 *             then the call fails with FPGA_INVALID_PARAM.<br>
 *             Repeat for fpgaUnregisterEvent.<br>
 *             Repeat for fpgaDestroyEventHandle.<br>
 *
 */
TEST_P(events_p, irq_event_05) {
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT,
                                       NULL, 0));
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT,
                                         NULL));
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaDestroyEventHandle(NULL));
}

/**
 * @test       irq_event_06
 *
 * @brief      Given a driver with IRQ support<br>
 *             when fpgaRegisterEvent is called for<br>
 *             an FPGA_DEVICE and FPGA_EVENT_INTERRUPT<br>
 *             then the call fails with FPGA_INVALID_PARAM.<br>
 *             Repeat for fpgaUnregisterEvent.<br>
 */
TEST_P(events_p, irq_event_06) {
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaRegisterEvent(handle_dev_, FPGA_EVENT_INTERRUPT,
                                       eh_, 0));
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(handle_dev_, FPGA_EVENT_INTERRUPT,
                                       eh_));
}

INSTANTIATE_TEST_CASE_P(events, events_p,
                        ::testing::ValuesIn(test_platform::platforms({ "dfl-n3000", "dfl-d5005", "dfl-n6000" })));


class events_dcp_p : public events_p {};

/**
 * @test       send_port_event_request
 * @brief      When passed a valid event handle, handle and flag.
 *             It returns FPGA_OK for dcp only.
 */
TEST_P(events_dcp_p, invalid_port_event_request){
  int port_op = FPGA_IRQ_ASSIGN;
  auto res = send_port_event_request(handle_accel_,eh_,port_op);
  EXPECT_EQ(FPGA_OK, res) << "\t result is " << res;

  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  res = send_port_event_request(handle_accel_,eh_,port_op);
  EXPECT_EQ(FPGA_OK, res);
}

/**
 * @test       send_fme_event_request
 * @brief      When passed a valid event handle, handle and flag.
 *             It returns FPGA_OK for dcp only.
 */
TEST_P(events_dcp_p, invalid_fme_event_request){
  int fme_op = FPGA_IRQ_ASSIGN;
  auto res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_OK, res) << "\t result is " << res;

  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_OK, res);
}

INSTANTIATE_TEST_CASE_P(events, events_dcp_p,
                        ::testing::ValuesIn(test_platform::hw_platforms({ "dfl-n3000","dfl-d5005" })));


class events_mcp_p : public events_p {};

/**
 * @test       send_port_event_request
 * @brief      When passed a valid event handle, handle and flag.
 *             It returns FPGA_NOT_SUPPORTED if interrupt is not
 *             supported or ioctl fails.
 */
TEST_P(events_mcp_p, invalid_port_event_request){
  int port_op = FPGA_IRQ_ASSIGN;
  auto res = send_port_event_request(handle_accel_,eh_,port_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED, res) << "\t result is " << res;

  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  res = send_port_event_request(handle_accel_,eh_,port_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED, res);
}

/**
 * @test       send_fme_event_request
 * @brief      When passed a valid event handle, handle and flag.
 *             It returns FPGA_NOT_SUPPORTED if interrupt is not
 *             supported or ioctl fails.
 */
TEST_P(events_mcp_p, invalid_fme_event_request){
  int fme_op = FPGA_IRQ_ASSIGN;
  auto res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res) << "\t result is " << res;

  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);
}

INSTANTIATE_TEST_CASE_P(events, events_mcp_p,
                        ::testing::ValuesIn(test_platform::platforms({ "dfl-d5005" })));



class events_mock_p : public events_p {
};

/**
 * @test       register_event_02
 *
 * @brief      When a valid fpga_event_handle and event types
 *             are passed to fpgaRegisterEvent and fpgaUnregisterEvent.
 *             both API calls return FPGA_OK.
 */
TEST_P(events_mock_p, register_event_02) {
  fpga_result res;
  ASSERT_EQ(res = xfpga_fpgaRegisterEvent(handle_dev_, FPGA_EVENT_POWER_THERMAL, eh_, 0),
            FPGA_OK)
      << "\tEVENT TYPE: ERROR, RESULT: " << fpgaErrStr(res);
  EXPECT_EQ(res = xfpga_fpgaUnregisterEvent(handle_dev_, FPGA_EVENT_POWER_THERMAL, eh_),
            FPGA_OK)
      << "\tRESULT: " << fpgaErrStr(res);
}

/**
 * @test       send_fme_event_request
 *
 * @brief      When passed a valid event handle, handle
 *             with FPGA_IRQ_ASSIGN flag.
 *             The function return FPGA_OK.
 *
 */
TEST_P(events_mock_p, valid_fme_event_request){
  int fme_op = FPGA_IRQ_ASSIGN;

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  auto res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_OK,res);
}

/**
 * @test       send_port_event_request
 * @brief      When passed a valid event handle and handle
 *             with FPGA_IRQ_ASSIGN flag. The function 
 *             returns FPGA_OK.
 */
TEST_P(events_mock_p, valid_port_event_request){
  int port_op = FPGA_IRQ_ASSIGN;

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  auto res = send_port_event_request(handle_accel_,eh_,port_op);
  EXPECT_EQ(FPGA_OK,res);
}

/**
 * @test       send_port_event_request
 * @brief      When passed a valid event handle and handle
 *             with FPGA_IRQ_DEASSIGN flag. The function 
 *             returns FPGA_OK.
 */
TEST_P(events_mock_p, valid_port_event_request_01){
  int port_op = FPGA_IRQ_DEASSIGN;

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  auto res = send_port_event_request(handle_accel_,eh_,port_op);
  EXPECT_EQ(FPGA_OK,res);
}

/**
 * @test       send_fme_event_request
 *
 * @brief      When passed a valid event handle and handle
 *             with FPGA_IRQ_DEASSIGN flag. The function 
 *             returns FPGA_OK.
 *
 */
TEST_P(events_mock_p, valid_fme_event_request_01){
  int fme_op = FPGA_IRQ_DEASSIGN;

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  auto res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_OK,res);
}

/**
 * @test       send_uafu_event_request
 * @brief      When passed a valid event handle and handle
 *             with FPGA_IRQ_ASSIGN flag. The function 
 *             returns FPGA_OK.
 */
TEST_P(events_mock_p, valid_uafu_event_request){
  int port_op = FPGA_IRQ_ASSIGN;

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dfl_get_port_uint_irq);
  auto res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_OK,res);
}

/**
 * @test       send_uafu_event_request
 * @brief      When passed a valid handle
 *             with an event handle that hasn't been assigned
 *             and with FPGA_IRQ_DEASSIGN in the flag. The function
 *             returns FPGA_INVALID_PARAM.
 */
TEST_P(events_mock_p, valid_uafu_event_request_01){
  int port_op = FPGA_IRQ_DEASSIGN;

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dfl_get_port_uint_irq);
  auto res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM, res);
}

/**
 * @test       send_uafu_event_request
 * @brief      When passed a valid event handle, handle and port params
 *             but an invalid interrupt num. It returns FPGA_INVALID_PARAM.
 */
TEST_P(events_mock_p, invalid_uafu_event_request_03){
  int port_op = FPGA_IRQ_ASSIGN;
  gEnableIRQ = true;

  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dummy_ioctl<-1, EINVAL>);
  auto res = send_uafu_event_request(handle_dev_,eh_,2,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);
}

/**
 * @test       afu_driver_register_event
 * @brief      Given invalid flags to driver_register_event, it
 *             returns FPGA_INVALID_PARAM. FPGA_EVENT_POWER_THERMAL 
 *             is not supported. 
 */
TEST_P(events_mock_p, afu_driver_register_event){
  int port_op = FPGA_IRQ_ASSIGN;

  // Valid params
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  auto res = driver_register_event(handle_accel_, FPGA_EVENT_ERROR, eh_, 0);
  EXPECT_EQ(FPGA_OK,res);

  // Invalid num_uafu_irqs
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  res = driver_register_event(handle_accel_, FPGA_EVENT_INTERRUPT, eh_, port_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);

  // Not supported event type
  res = driver_register_event(handle_accel_, FPGA_EVENT_POWER_THERMAL, eh_, 0);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);
}

/**
 * @test       fme_driver_register_event
 * @brief      Given invalid flags to driver_register_event, it
 *             returns FPGA_INVALID_PARAM. 
 */
TEST_P(events_mock_p, fme_driver_register_event){
  // Invalid ioctl
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  auto res = driver_register_event(handle_dev_, FPGA_EVENT_ERROR, eh_, 0);
  EXPECT_EQ(FPGA_OK,res);

  res = driver_register_event(handle_dev_, FPGA_EVENT_INTERRUPT, eh_, 0);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);
}

/**
 * @test       fme_driver_unregister_event
 * @brief      Given invalid event type to fme, driver_unregister_event
 *             returns FPGA_INVALID_PARAM.
 */
TEST_P(events_mock_p, fme_driver_unregister_event){
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  auto res = driver_unregister_event(handle_dev_, FPGA_EVENT_ERROR, eh_);
  EXPECT_EQ(FPGA_OK,res);

  // Not supported event_type
  res = driver_unregister_event(handle_dev_, FPGA_EVENT_INTERRUPT, eh_);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);
}

/**
 * @test       event_drv_13
 *
 * @brief      When register a valid event handle, FPGA_EVENT_INTERRUPT
 *             xfpga_fpgaRegisterEvent() returns FPGA_OK.
 *
 */
TEST_P(events_mock_p, event_drv_13) {
  fpga_event_handle bad_handle;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));

  // Reset event handle magic
  EXPECT_EQ(FPGA_OK, xfpga_fpgaRegisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT, bad_handle, 0));

  // Destroy event handle
  auto res = xfpga_fpgaDestroyEventHandle(&bad_handle);
  EXPECT_EQ(FPGA_OK, res);
}

/**
 * @test       event_drv_14
 *
 * @brief      When passed an event handle with an invalid magic
 *             xfpga_fpgaUnregisterEvent() returns FPGA_INVALID_PARAM.
 *
 */
TEST_P(events_mock_p, event_drv_14) {
  fpga_event_handle bad_handle;
  EXPECT_EQ(FPGA_OK, xfpga_fpgaCreateEventHandle(&bad_handle));

  // Valid magic and ioctl
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dfl_get_port_uint_irq);
  EXPECT_EQ(FPGA_INVALID_PARAM, xfpga_fpgaUnregisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT, bad_handle));

  // Destory event handle
  auto res = xfpga_fpgaDestroyEventHandle(&bad_handle);
  EXPECT_EQ(FPGA_OK, res);
}

/**
 * @test       send_fme_event_request
 * @brief      When passed a valid event handle but invalid fme params.
 *             It returns FPGA_INVALID_PARAM
 */
TEST_P(events_mock_p, invalid_fme_event_request_01){
  int fme_op = 0;
  auto res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  fme_op = FPGA_IRQ_ASSIGN;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dummy_ioctl<-1,EINVAL>);

  res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_SET_IRQ, dummy_ioctl<-1,EINVAL>);
  res = send_fme_event_request(handle_dev_,eh_,fme_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);
}

/**
 * @test       send_port_event_request
 *
 * @brief      When passed a valid event handle but invalid port params.
 *             It returns FPGA_INVALID_PARAM
 *
 */
TEST_P(events_mock_p, invalid_port_event_request_01){
  int port_op = 0;
  auto res = send_port_event_request(handle_dev_,eh_,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  port_op = FPGA_IRQ_ASSIGN;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dummy_ioctl<-1,EINVAL>);

  res = send_port_event_request(handle_dev_,eh_,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_SET_IRQ, set_dummy_dfl_irq);
  res = send_port_event_request(handle_dev_,eh_,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);
}

/**
 * @test       send_uafu_event_request
 * @brief      When passed a valid event handle but invalid port params.
 *             It returns FPGA_INVALID_PARAM. When ioctl fails,
 *             it returns FPGA_EXCEPTION.
 */
TEST_P(events_mock_p, invalid_uafu_event_request_01){
  // invalid port operation
  int port_op = 0;
  auto res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  // Invalid ioctl
  port_op = FPGA_IRQ_ASSIGN;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dummy_ioctl<-1, EINVAL>);
  res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);
}

/**
 * @test       send_uafu_event_request
 * @brief      When passed a valid event handle, handle and port params.
 *             It returns FPGA_EXCEPTION when ioctl fails.
 */
TEST_P(events_mock_p, invalid_uafu_event_request_02){
  int port_op = FPGA_IRQ_ASSIGN;
  auto res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res) << "\t result is " << res;

  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dfl_get_port_uint_irq);
  res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);

  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dfl_get_port_uint_irq);
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_SET_IRQ, set_dummy_dfl_irq);
  res = send_uafu_event_request(handle_dev_,eh_,0,port_op);
  EXPECT_EQ(FPGA_EXCEPTION,res);
}

/**
 * @test       fme_interrupts_check
 * @brief      When irq is not supported and register invalid ioctl,
 *             check_err_interrupts_supported returns FPGA_NOT_SUPPORTED
 *             or FPGA_EXCEPTION.
 */
TEST_P(events_mock_p, fme_interrupts_check){
  fpga_objtype obj;
  auto h = (struct _fpga_handle*)handle_dev_;
  auto t = (struct _fpga_token*)h->token;

  // no fme_info capability
  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  auto res = check_err_interrupts_supported(handle_dev_,&obj);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);

  // Value input
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  res = check_err_interrupts_supported(handle_dev_,&obj);
  EXPECT_EQ(FPGA_OK,res);

  // interrupt ioctl
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dummy_ioctl<-1, EINVAL>);
  res = check_err_interrupts_supported(handle_dev_,&obj);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  // change sysfspath
  strncpy(t->sysfspath, "null" , 5);
  res = check_err_interrupts_supported(handle_dev_,&obj);
  EXPECT_NE(FPGA_OK,res);
}

/**
 * @test       afu_interrupts_check
 * @brief      When irq is not supported and register invalid ioctl,
 *             check_err_interrupts_supported returns FPGA_NOT_SUPPORTED 
 *             or FPGA_EXCEPTION.
 */
TEST_P(events_mock_p, afu_interrupts_check){
  fpga_objtype obj;
  auto h = (struct _fpga_handle*)handle_accel_;
  auto t = (struct _fpga_token*)h->token;

  // no fme_info capability
  gEnableIRQ = false;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  auto res = check_err_interrupts_supported(handle_accel_,&obj);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);

  // Value input
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  res = check_err_interrupts_supported(handle_accel_,&obj);
  EXPECT_EQ(FPGA_OK,res);

  // interrupt ioctl
    system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dummy_ioctl<-1, EINVAL>);

  res = check_err_interrupts_supported(handle_accel_,&obj);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  // change sysfspath
  strncpy(t->sysfspath, "null", 5);
  res = check_err_interrupts_supported(handle_accel_,&obj);
  EXPECT_NE(FPGA_OK,res);
}

/**
 * @test       afu_driver_unregister_event
 * @brief      Given invalid ioctls, driver_unregister_event returns
 *             FPGA_INVALID_PARAM.
 */
TEST_P(events_mock_p, afu_driver_unregister_event){
  // Invalid ioctl
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_SET_IRQ, dummy_ioctl<-1, EINVAL>);
  auto res = driver_unregister_event(handle_accel_, FPGA_EVENT_ERROR, eh_);
  EXPECT_EQ(FPGA_INVALID_PARAM,res);

  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_SET_IRQ, dummy_ioctl<-1, EINVAL>);
  res = driver_unregister_event(handle_accel_, FPGA_EVENT_INTERRUPT, eh_);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);

  // Not supported event_type
  res = driver_unregister_event(handle_accel_, FPGA_EVENT_POWER_THERMAL, eh_);
  EXPECT_EQ(FPGA_NOT_SUPPORTED,res);
}

/**
 * @test       irq_event_01
 *
 * @brief      Given a driver with IRQ support<br>
 *             when fpgaRegisterEvent is called for<br>
 *             an FPGA_DEVICE and FPGA_EVENT_ERROR<br>
 *             then the call is successful and<br>
 *             we can receive interrupt events on<br>
 *             the OS-specific object from the event handle.<br>
 */
TEST_P(events_mock_p, irq_event_01) {
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_GET_IRQ_NUM, dfl_get_fme_err_irq);
  system_->register_ioctl_handler(DFL_FPGA_FME_ERR_SET_IRQ, set_dfl_irq);

 
  ASSERT_EQ(FPGA_OK, xfpga_fpgaRegisterEvent(handle_dev_, FPGA_EVENT_ERROR,
                                       eh_, 0));
  int res;
  int fd = -1;

  EXPECT_EQ(FPGA_OK, xfpga_fpgaGetOSObjectFromEventHandle(eh_, &fd));
  EXPECT_GE(fd, 0);

  struct pollfd poll_fd;
  int maxpolls = 20;

  poll_fd.fd      = fd;
  poll_fd.events  = POLLIN | POLLPRI;
  poll_fd.revents = 0;

  do
  {
    res = poll(&poll_fd, 1, 1000);
    ASSERT_GE(res, 0);
    --maxpolls;
    ASSERT_GT(maxpolls, 0);
  } while(res == 0);

  EXPECT_EQ(res, 1);
  EXPECT_NE(poll_fd.revents, 0);

  EXPECT_EQ(FPGA_OK, xfpga_fpgaUnregisterEvent(handle_dev_, FPGA_EVENT_ERROR,
                                         eh_));
}

/**
 * @test       irq_event_02
 *
 * @brief      Given a driver with IRQ support<br>
 *             when fpgaRegisterEvent is called for<br>
 *             an FPGA_ACCELERATOR and FPGA_EVENT_ERROR<br>
 *             then the call is successful and<br>
 *             we can receive interrupt events on<br>
 *             the OS-specific object from the event handle.<br>
 *
 */
TEST_P(events_mock_p, irq_event_02) {
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_GET_IRQ_NUM, dfl_get_port_err_irq);
  system_->register_ioctl_handler(DFL_FPGA_PORT_ERR_SET_IRQ, set_dfl_irq);


 
  ASSERT_EQ(FPGA_OK, xfpga_fpgaRegisterEvent(handle_accel_, FPGA_EVENT_ERROR, eh_, 0));

  int res;
  int fd = -1;

  EXPECT_EQ(FPGA_OK, xfpga_fpgaGetOSObjectFromEventHandle(eh_, &fd));
  EXPECT_GE(fd, 0);

  struct pollfd poll_fd;
  int maxpolls = 20;

  poll_fd.fd      = fd;
  poll_fd.events  = POLLIN | POLLPRI;
  poll_fd.revents = 0;

  do
  {
    res = poll(&poll_fd, 1, 1000);
    ASSERT_GE(res, 0);
    --maxpolls;
    ASSERT_GT(maxpolls, 0);
  } while(res == 0);

  EXPECT_EQ(res, 1);
  EXPECT_NE(poll_fd.revents, 0);

  EXPECT_EQ(FPGA_OK, xfpga_fpgaUnregisterEvent(handle_accel_, FPGA_EVENT_ERROR, eh_));
}

/**
 * @test       irq_event_03
 *
 * @brief      Given a driver with IRQ support<br>
 *             when fpgaRegisterEvent is called for<br>
 *             an FPGA_ACCELERATOR and FPGA_EVENT_INTERRUPT<br>
 *             then the call is successful and<br>
 *             we can receive interrupt events on<br>
 *             the OS-specific object from the event handle.<br>
 *
 */
TEST_P(events_mock_p, irq_event_03) {
  gEnableIRQ = true;
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_GET_IRQ_NUM, dfl_get_port_uint_irq);
  system_->register_ioctl_handler(DFL_FPGA_PORT_UINT_SET_IRQ, set_dfl_irq);

 
  ASSERT_EQ(FPGA_OK, xfpga_fpgaRegisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT,
                                       eh_, 0));

  int res;
  int fd = -1;

  EXPECT_EQ(FPGA_OK, xfpga_fpgaGetOSObjectFromEventHandle(eh_, &fd));
  EXPECT_GE(fd, 0);

  struct pollfd poll_fd;
  int maxpolls = 20;

  poll_fd.fd      = fd;
  poll_fd.events  = POLLIN | POLLPRI;
  poll_fd.revents = 0;

  do
  {
    res = poll(&poll_fd, 1, 1000);
    ASSERT_GE(res, 0);
    --maxpolls;
    ASSERT_GT(maxpolls, 0);
  } while(res == 0);

  EXPECT_EQ(res, 1);
  EXPECT_NE(poll_fd.revents, 0);

  EXPECT_EQ(FPGA_OK, xfpga_fpgaUnregisterEvent(handle_accel_, FPGA_EVENT_INTERRUPT,
                                         eh_));
}

INSTANTIATE_TEST_CASE_P(events, events_mock_p,
                        ::testing::ValuesIn(test_platform::mock_platforms({ "dfl-n3000","dfl-d5005" })));
