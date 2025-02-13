// Copyright(c) 2021, Intel Corporation
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

extern "C" {

#include <json-c/json.h>
#include <uuid/uuid.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "opae_int.h"
}

#include <opae/fpga.h>
#include "intel-fpga.h"
#include <linux/ioctl.h>

#include <cstdlib>
#include <string>
#include <regex>
#include "gtest/gtest.h"
#include "mock/test_system.h"
#include "libboard/board_common/board_common.h"
#include "libboard/board_n6000/board_n6000.h"

using namespace opae::testing;

class board_n6000_c_p : public ::testing::TestWithParam<std::string> {
protected:
	board_n6000_c_p() : tokens_{ {nullptr, nullptr} } {}

	fpga_result write_sysfs_file(const char *file,
		void *buf, size_t count);
	ssize_t eintr_write(int fd, void *buf, size_t count);
	fpga_result delete_sysfs_file(const char *file);

	virtual void SetUp() override {
		ASSERT_TRUE(test_platform::exists(GetParam()));
		platform_ = test_platform::get(GetParam());
		system_ = test_system::instance();
		system_->initialize();
		system_->prepare_syfs(platform_);

		filter_ = nullptr;
		ASSERT_EQ(fpgaInitialize(NULL), FPGA_OK);
		ASSERT_EQ(fpgaGetProperties(nullptr, &filter_), FPGA_OK);
		ASSERT_EQ(fpgaPropertiesSetObjectType(filter_, FPGA_DEVICE), FPGA_OK);
		num_matches_ = 0;
		ASSERT_EQ(fpgaEnumerate(&filter_, 1, tokens_.data(), tokens_.size(),
			&num_matches_), FPGA_OK);
		EXPECT_GT(num_matches_, 0);
		dev_ = nullptr;
		ASSERT_EQ(fpgaOpen(tokens_[0], &dev_, 0), FPGA_OK);
	}

	virtual void TearDown() override {
		EXPECT_EQ(fpgaDestroyProperties(&filter_), FPGA_OK);
		if (dev_) {
			EXPECT_EQ(fpgaClose(dev_), FPGA_OK);
			dev_ = nullptr;
		}
		for (auto &t : tokens_) {
			if (t) {
				EXPECT_EQ(fpgaDestroyToken(&t), FPGA_OK);
				t = nullptr;
			}
		}
		fpgaFinalize();
		system_->finalize();
	}

	std::array<fpga_token, 2> tokens_;
	fpga_properties filter_;
	fpga_handle dev_;
	test_platform platform_;
	uint32_t num_matches_;
	test_system *system_;
};

ssize_t board_n6000_c_p::eintr_write(int fd, void *buf, size_t count)
{
	ssize_t bytes_written = 0, total_written = 0;
	char *ptr = (char*)buf;

	if (!buf) {
		return -1;
	}

	while (total_written < (ssize_t)count) {
		bytes_written =
			write(fd, ptr + total_written, count - total_written);
		if (bytes_written < 0) {
			if (errno == EINTR) {
				continue;
			}
			return bytes_written;
		}
		total_written += bytes_written;
	}
	return total_written;

}
fpga_result board_n6000_c_p::write_sysfs_file(const char *file,
	void *buf, size_t count) {
	fpga_result res = FPGA_OK;
	char sysfspath[SYSFS_PATH_MAX];
	int fd = 0;

	snprintf(sysfspath, sizeof(sysfspath),
		 "%s/%s", "/sys/class/fpga_region/region*/dfl-fme*", file);

	glob_t pglob;
	int gres = glob(sysfspath, GLOB_NOSORT, NULL, &pglob);
	if ((gres) || (1 != pglob.gl_pathc)) {
		globfree(&pglob);
		return FPGA_NOT_FOUND;
	}
	fd = open(pglob.gl_pathv[0], O_WRONLY);
	globfree(&pglob);
	if (fd < 0) {
		printf("open failed \n");
		return FPGA_NOT_FOUND;
	}

	ssize_t total_written = eintr_write(fd, buf, count);
	if (total_written == 0) {
		close(fd);
		printf("total_written failed \n");
		return FPGA_INVALID_PARAM;
	}

	close(fd);
	return res;
}

fpga_result board_n6000_c_p::delete_sysfs_file(const char *file) {
	fpga_result res = FPGA_OK;
	char sysfspath[SYSFS_PATH_MAX];
	int status = 0;

	snprintf(sysfspath, sizeof(sysfspath),
		 "%s/%s", "/sys/class/fpga_region/region*/dfl-fme*", file);

	glob_t pglob;
	int gres = glob(sysfspath, GLOB_NOSORT, NULL, &pglob);
	if ((gres) || (1 != pglob.gl_pathc)) {
		globfree(&pglob);
		return FPGA_NOT_FOUND;
	}

	status = remove(pglob.gl_pathv[0]);

	globfree(&pglob);
	if (status < 0) {
		printf("delete failed = %d \n", status);
		return FPGA_NOT_FOUND;
	}

	return res;
}

// test DFL sysfs attributes
class board_dfl_n6000_c_p : public board_n6000_c_p {

protected:
	void erase_bom_info(
		const char * const bom_info_nvmem,
		char * const bom_info,
		size_t bom_info_size);
	void test_bom_info(
		const fpga_token token,
		const char * const bom_info_nvmem,
		char * const bom_info_in,
		const char * const bom_info_out);
};
/**
* @test       board_n6000_1
* @brief      Tests: read_bmcfw_version
* @details    Validates bmc firmware version  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_1) {

	char bmcfw_ver[SYSFS_PATH_MAX];

	EXPECT_EQ(read_bmcfw_version(tokens_[0], bmcfw_ver, SYSFS_PATH_MAX), FPGA_OK);

	EXPECT_EQ(read_bmcfw_version(tokens_[0], NULL, SYSFS_PATH_MAX), FPGA_INVALID_PARAM);

	EXPECT_EQ(read_bmcfw_version(NULL, bmcfw_ver, SYSFS_PATH_MAX), FPGA_INVALID_PARAM);
}

/**
* @test       board_n6000_2
* @brief      Tests: read_max10fw_version
* @details    Validates max10 firmware version  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_2) {

	char max10fw_ver[SYSFS_PATH_MAX];

	EXPECT_EQ(read_max10fw_version(tokens_[0], max10fw_ver, SYSFS_PATH_MAX), FPGA_OK);

	EXPECT_EQ(read_max10fw_version(tokens_[0], NULL, SYSFS_PATH_MAX), FPGA_INVALID_PARAM);

	EXPECT_EQ(read_max10fw_version(NULL, max10fw_ver, SYSFS_PATH_MAX), FPGA_INVALID_PARAM);
}

/**
* @test       board_n6000_3
* @brief      Tests: parse_fw_ver
* @details    Validates parse fw version  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_3) {

	char buf[SYSFS_PATH_MAX];
	char fw_ver[SYSFS_PATH_MAX];

	EXPECT_EQ(parse_fw_ver(buf, NULL, SYSFS_PATH_MAX), FPGA_INVALID_PARAM);
	EXPECT_EQ(parse_fw_ver(NULL, fw_ver, SYSFS_PATH_MAX), FPGA_INVALID_PARAM);
}

/**
* @test       board_n6000_4
* @brief      Tests: print_sec_info
* @details    Validates fpga security info  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_4) {

	EXPECT_EQ(print_sec_info(tokens_[0]), FPGA_OK);
}

/**
* @test       board_n6000_5
* @brief      Tests: print_mac_info
* @details    Validates prints mac info  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_5) {

	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);
}

/**
* @test       board_n6000_6
* @brief      Tests: print_board_info
* @details    Validates fpga board info  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_6) {

	EXPECT_EQ(print_board_info(tokens_[0]), FPGA_OK);
}

/**
* @test       board_n6000_8
* @brief      Tests: print_phy_info
* @details    Validates fpga phy group info  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_8) {

	EXPECT_EQ(print_phy_info(tokens_[0]), FPGA_NOT_SUPPORTED);
}

/**
* @test       board_n6000_9
* @brief      Tests: read_max10fw_version
*             read_bmcfw_version,
* @details    Validates fpga invalid fpga firmware version  <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_9) {

	char buf[10] = { 0 };
	memset(&buf, 0xf, sizeof(buf));

	ASSERT_EQ(write_sysfs_file((const char *)"dfl_dev*/bmcfw_version", (void*)buf, sizeof(buf)), FPGA_OK);
	char bmcfw_ver[SYSFS_PATH_MAX];
	EXPECT_NE(read_bmcfw_version(tokens_[0], bmcfw_ver, SYSFS_PATH_MAX), FPGA_OK);

	ASSERT_EQ(write_sysfs_file((const char *)"dfl_dev*/bmc_version", (void*)buf, sizeof(buf)), FPGA_OK);
	char max10fw_ver[SYSFS_PATH_MAX];
	EXPECT_NE(read_max10fw_version(tokens_[0], max10fw_ver, SYSFS_PATH_MAX), FPGA_OK);
}

/**
* @test       board_n6000_10
* @brief      Tests: print_phy_info
* @details    invalid print phy info input <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_10) {

	EXPECT_NE(print_phy_info(tokens_[0]), FPGA_OK);
	EXPECT_NE(print_phy_info(NULL), FPGA_OK);
}

void board_dfl_n6000_c_p::erase_bom_info(
	const char * const bom_info_nvmem,
	char * const bom_info,
	const size_t bom_info_size)
{
	EXPECT_NE(bom_info_nvmem, (char *)NULL);
	EXPECT_NE(bom_info, (char *)NULL);

	// Fill whole BOM Critical Components with 0xFF:
	memset(bom_info, 0xFF, bom_info_size);
	ASSERT_EQ(write_sysfs_file(bom_info_nvmem, bom_info, bom_info_size), FPGA_OK);
}

void board_dfl_n6000_c_p::test_bom_info(
	const fpga_token token,
	const char * const bom_info_nvmem,
	char * const bom_info_in,
	const char * const bom_info_out)
{
	EXPECT_NE(bom_info_nvmem, (char *)NULL);
	EXPECT_NE(bom_info_in, (char * )NULL);
	EXPECT_NE(bom_info_out, (char *)NULL);

	size_t bom_info_in_length = strlen(bom_info_in);
	if (bom_info_in_length > 0) {
		ASSERT_EQ(write_sysfs_file(bom_info_nvmem, bom_info_in, bom_info_in_length), FPGA_OK);
	}

	testing::internal::CaptureStdout();
	EXPECT_EQ(print_board_info(token), FPGA_OK);
	std::string stdout = testing::internal::GetCapturedStdout();
	std::regex reg(bom_info_out, std::regex::extended);
	bool match_found = std::regex_match(stdout.c_str(), reg);
	EXPECT_EQ(match_found, true);
}

/**
* @test       board_n6000_11
* @brief      Tests: print_board_info
* @details    checks BOM Critical Components specific output from print_board_info<br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_11) {

	const char * const bom_info_nvmem = "dfl_dev*/*/bom_info0/nvmem";
	const char * const last_board_info = ".*Board Management Controller Build version:.*\n";
	const size_t FPGA_BOM_INFO_NVMEM_SIZE = 0x2000;
	static char bom_info_in[FPGA_BOM_INFO_NVMEM_SIZE];
	static char bom_info_out[2 * FPGA_BOM_INFO_NVMEM_SIZE];

	// Test different line endings and white space
	// and no NUL termination:
	erase_bom_info(bom_info_nvmem, bom_info_in, sizeof(bom_info_in));
	strcpy(bom_info_in,
		"Name1,Value\n"
		"\n"
		"Name2,Value2\r\n"
		"Name3, Value3\n\r"
		"BOM PBA#,B#FB2CG2@AGF14-A1P2\r\n"
		"BOM MMID, 115000\r\r\r"
		"ABC3 ,This is a demo\r"
		"C cd     	,	 			   s\xFF");
	strcpy(bom_info_out,
		".*"
		"Name1: Value\n"
		"Name2: Value2\n"
		"Name3: Value3\n"
		"BOM PBA#: B#FB2CG2@AGF14-A1P2\n"
		"BOM MMID: 115000\n"
		"ABC3: This is a demo\n"
		"C cd: s\n");
	test_bom_info(tokens_[0], bom_info_nvmem, bom_info_in, bom_info_out);


	// Corner case: test completely empty BOM Critical Components (filled with
	// FF):
	erase_bom_info(bom_info_nvmem, bom_info_in, sizeof(bom_info_in));
	strcpy(bom_info_in, "");
	test_bom_info(tokens_[0], bom_info_nvmem, bom_info_in, last_board_info);


	// Corner case: test completely filled BOM Critical Components
	// and no NUL termination:
	size_t bom_info_length = 0;
	const char *keyValue;

	erase_bom_info(bom_info_nvmem, bom_info_in, sizeof(bom_info_in));
	strcpy(bom_info_in, "");
	strcpy(bom_info_out, "");
	for (size_t i = 0; i < 60; ++i) {
		keyValue =
			"looooooooooooooooooooooooooooooooooooo"
			"oooooooooooooooooooooooong_key\t \t , \t \t"
			"loooooooooooooooooooooooooooooooooooooo"
			"ooooooooooong_value\n";
		strcat(bom_info_in, keyValue);
		bom_info_length += strlen(keyValue);
	}
	keyValue = "looong_key \t \t,\t \t looong_value\n";
	strcat(bom_info_in, keyValue);
	bom_info_length += strlen(keyValue);
	EXPECT_EQ(bom_info_length, sizeof(bom_info_in)); // Verify complete fill

	bom_info_length = 0;
	strcpy(bom_info_out, last_board_info);
	for (size_t i = 0; i < 60; ++i) {
		keyValue =
			"looooooooooooooooooooooooooooooooooooo"
			"oooooooooooooooooooooooong_key: "
			"loooooooooooooooooooooooooooooooooooooo"
			"ooooooooooong_value\n";
		strcat(bom_info_out, keyValue);
		bom_info_length += strlen(keyValue);
	}
	keyValue = "looong_key: looong_value\n";
	bom_info_length += strlen(keyValue);
	strcat(bom_info_out, keyValue);

	test_bom_info(tokens_[0], bom_info_nvmem, bom_info_in, bom_info_out);
}

/**
* @test       board_n6000_12
* @brief      Tests: print_mac_info
* @details    prints mac address <br>
*/
TEST_P(board_dfl_n6000_c_p, board_n6000_12) {

	char mac_buf[18] = { 0 };
	strncpy(mac_buf, "ff:ff:ff:ff:ff:ff", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	char mac_count[2] = { 0 };
	strncpy(mac_count, "8", 2);
	write_sysfs_file((char*)"dfl_dev*/mac_count",
		(void*)mac_count, 2);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_EXCEPTION);


	strncpy(mac_buf, "78:56:34:12:AB:90", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);


    strncpy(mac_buf, "78:56:34:12:AB:FE", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

	strncpy(mac_buf, "78:56:34:12:FF:FF", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

	strncpy(mac_buf, "78:56:34:FE:FF:FF", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);


    strncpy(mac_buf, "78:56:34:FF:FF:FF", 18);
    write_sysfs_file((char*)"dfl_dev*/mac_address",
        (void*)mac_buf, 18);
    EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

	strncpy(mac_buf, "78:56:FF:FF:FF:FF", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

	strncpy(mac_buf, "78:FF:FF:FF:FF:FF", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

	strncpy(mac_buf, "FE:FF:FF:FF:FF:FF", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

	strncpy(mac_buf, "00:00:00:00:00:ff", 18);
	write_sysfs_file((char*)"dfl_dev*/mac_address",
		(void*)mac_buf, 18);
	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_OK);

}
INSTANTIATE_TEST_CASE_P(board_dfl_n6000_c, board_dfl_n6000_c_p,
	::testing::ValuesIn(test_platform::mock_platforms({ "dfl-n6000" })));

// test invalid sysfs attributes
class board_n6000_invalid_c_p : public board_n6000_c_p { };

/**
* @test       board_n6000_11
* @brief      Tests: read_max10fw_version
*             read_bmcfw_version
*             read_mac_info
*             print_board_info
*             print_phy_info
*             print_mac_info
* @details    Validates function with invalid sysfs <br>
*/
TEST_P(board_n6000_invalid_c_p, board_n6000_11) {

	char bmcfw_ver[SYSFS_PATH_MAX];
	EXPECT_EQ(read_bmcfw_version(tokens_[0], bmcfw_ver, SYSFS_PATH_MAX), FPGA_NOT_FOUND);

	char max10fw_ver[SYSFS_PATH_MAX];
	EXPECT_EQ(read_max10fw_version(tokens_[0], max10fw_ver, SYSFS_PATH_MAX), FPGA_NOT_FOUND);

	EXPECT_EQ(print_board_info(tokens_[0]), FPGA_NOT_FOUND);

	EXPECT_EQ(print_mac_info(tokens_[0]), FPGA_NOT_FOUND);
	EXPECT_EQ(print_sec_info(tokens_[0]), FPGA_NOT_FOUND);

	EXPECT_NE(print_phy_info(tokens_[0]), FPGA_EXCEPTION);
}
INSTANTIATE_TEST_CASE_P(board_n6000_invalid_c, board_n6000_invalid_c_p,
	::testing::ValuesIn(test_platform::mock_platforms({ "skx-p" })));
