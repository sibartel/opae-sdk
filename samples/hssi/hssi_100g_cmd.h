// Copyright(c) 2020-2021, Intel Corporation
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
#pragma once
#include "hssi_cmd.h"

#define CSR_SCRATCH     0x1000
#define CSR_BLOCK_ID    0x1001
#define CSR_PKT_SIZE    0x1008
#define CSR_CTRL0       0x1009
#define CSR_CTRL1       0x1010
#define CSR_DST_ADDR_LO 0x1011
#define CSR_DST_ADDR_HI 0x1012
#define CSR_SRC_ADDR_LO 0x1013
#define CSR_SRC_ADDR_HI 0x1014
#define CSR_RX_COUNT    0x1015
#define CSR_MLB_RST     0x1016
#define CSR_TX_COUNT    0x1017

#define STOP_BITS       0xa

class hssi_100g_cmd : public hssi_cmd
{
public:
  hssi_100g_cmd()
    : port_(0)
    , eth_loopback_("on")
    , num_packets_(1)
    , gap_("none")
    , pattern_("random")
    , src_addr_("11:22:33:44:55:66")
    , dest_addr_("77:88:99:aa:bb:cc")
    , eth_ifc_("none")
    , start_size_(64)
    , end_size_(9600)
    , end_select_("pkt_num")
  {}

  virtual const char *name() const override
  {
    return "hssi_100g";
  }

  virtual const char *description() const override
  {
    return "hssi 100G test\n";
  }

  virtual void add_options(CLI::App *app) override
  {
    auto opt = app->add_option("--port", port_,
                               "QSFP port");
    opt->check(CLI::Range(0, 7))->default_str(std::to_string(port_));

    opt = app->add_option("--eth-loopback", eth_loopback_,
                    "whether to enable loopback on the eth interface");
    opt->check(CLI::IsMember({"on", "off"}))->default_str(eth_loopback_);

    opt = app->add_option("--num-packets", num_packets_,
                          "number of packets");
    opt->default_str(std::to_string(num_packets_));

    opt = app->add_option("--gap", gap_,
                          "inter-packet gap");
    opt->check(CLI::IsMember({"random", "none"}))->default_str(gap_);

    opt = app->add_option("--pattern", pattern_,
                          "pattern mode");
    opt->check(CLI::IsMember({"random", "fixed", "increment"}))->default_str(pattern_);

    opt = app->add_option("--src-addr", src_addr_,
                          "source MAC address");
    opt->default_str(src_addr_);

    opt = app->add_option("--dest-addr", dest_addr_,
                          "destination MAC address");
    opt->default_str(dest_addr_);

    opt = app->add_option("--eth-ifc", eth_ifc_,
                          "ethernet interface name");
    opt->default_str(eth_ifc_);

    opt = app->add_option("--start-size", start_size_,
                          "packet size in bytes (lower limit for incr mode)");
    opt->default_str(std::to_string(start_size_));

    opt = app->add_option("--end-size", end_size_,
                          "upper limit of packet size in bytes");
    opt->default_str(std::to_string(end_size_));

    opt = app->add_option("--end-select", end_select_,
                          "end of packet generation control");
    opt->check(CLI::IsMember({"pkt_num", "gen_idle"}))->default_str(end_select_);
  }

  virtual int run(test_afu *afu, CLI::App *app) override
  {
    (void)app;

    hssi_afu *hafu = dynamic_cast<hssi_afu *>(afu);

    uint64_t bin_src_addr = mac_bits_for(src_addr_);
    if (bin_src_addr == INVALID_MAC) {
      std::cerr << "invalid MAC address: " << src_addr_ << std::endl;
      return test_afu::error;
    }

    uint64_t bin_dest_addr = mac_bits_for(dest_addr_);
    if (bin_dest_addr == INVALID_MAC) {
      std::cerr << "invalid MAC address: " << dest_addr_ << std::endl;
      return test_afu::error;
    }

    std::string eth_ifc = eth_ifc_;
    if (eth_ifc == "none")
      eth_ifc = hafu->ethernet_interface();

    std::cout << "100G loopback test" << std::endl
              << "  port: " << port_ << std::endl
              << "  eth_loopback: " << eth_loopback_ << std::endl
              << "  num_packets: " << num_packets_ << std::endl
              << "  gap: " << gap_ << std::endl
              << "  src_address: " << src_addr_ << std::endl
              << "    (bits): 0x" << std::hex << bin_src_addr << std::endl
              << "  dest_address: " << dest_addr_ << std::endl
              << "    (bits): 0x" << std::hex << bin_dest_addr << std::endl
              << "  pattern: " << pattern_ << std::endl
              << "  start size: " << start_size_ << std::endl
              << "  end size: " << end_size_ << std::endl
              << "  end select: " << end_select_ << std::endl
              << "  eth: " << eth_ifc << std::endl
              << std::endl;

    if (eth_ifc == "") {
      std::cout << "No eth interface, so not "
                   "honoring --eth-loopback." << std::endl;
    } else {
      if (eth_loopback_ == "on")
        enable_eth_loopback(eth_ifc, true);
      else
        enable_eth_loopback(eth_ifc, false);
    }

    hafu->mbox_write(CSR_CTRL1, STOP_BITS);

    hafu->write64(TRAFFIC_CTRL_PORT_SEL, port_);

    uint32_t reg;

    reg = start_size_ | (end_size_ << 16);
    hafu->mbox_write(CSR_PKT_SIZE, reg);

    reg = num_packets_;
    if (reg)
      reg |= 0x80000000;
    hafu->mbox_write(CSR_CTRL0, reg);

    hafu->mbox_write(CSR_SRC_ADDR_LO, static_cast<uint32_t>(bin_src_addr));
    hafu->mbox_write(CSR_SRC_ADDR_HI, static_cast<uint32_t>(bin_src_addr >> 32));

    hafu->mbox_write(CSR_DST_ADDR_LO, static_cast<uint32_t>(bin_dest_addr));
    hafu->mbox_write(CSR_DST_ADDR_HI, static_cast<uint32_t>(bin_dest_addr >> 32));

    reg = 0;
    if (gap_ == "random")
      reg |= 1 << 7;

    if (end_select_ == "pkt_num")
      reg |= 1 << 6;

    if (pattern_ == "fixed")
      reg |= 1 << 4;
    else if (pattern_ == "increment")
      reg |= 2 << 4;

    if (eth_loopback_ == "off")
      reg |= 1 << 3;

    hafu->mbox_write(CSR_CTRL1, reg);

    uint32_t count;
    const uint64_t interval = 100ULL;
    do
    {
      count = hafu->mbox_read(CSR_TX_COUNT);

      if (!running_) {
        hafu->mbox_write(CSR_CTRL1, STOP_BITS);
        return test_afu::error;
      }

      std::this_thread::sleep_for(std::chrono::microseconds(interval));
    } while(count < num_packets_);

    print_registers(std::cout, hafu);

    std::cout << std::endl;

    if (eth_ifc == "") {
      std::cout << "No eth interface, so not "
                   "showing stats." << std::endl;
    } else {
      show_eth_stats(eth_ifc);

      if (eth_loopback_ == "on")
        enable_eth_loopback(eth_ifc, false);
    }

    return test_afu::success;
  }

  virtual const char *afu_id() const override
  {
    return "43425ee6-92b2-4742-b03a-bd8d4a533812";
  }

  std::ostream & print_registers(std::ostream &os, hssi_afu *hafu) const
  {
    os << "0x40000 " << std::setw(21) << "ETH_AFU_DFH" << ": " <<
      int_to_hex(hafu->read64(ETH_AFU_DFH)) << std::endl;
    os << "0x40008 " << std::setw(21) << "ETH_AFU_ID_L" << ": " <<
      int_to_hex(hafu->read64(ETH_AFU_ID_L)) << std::endl;
    os << "0x40010 " << std::setw(21) << "ETH_AFU_ID_H" << ": " <<
      int_to_hex(hafu->read64(ETH_AFU_ID_H)) << std::endl;
    os << "0x40030 " << std::setw(21) << "TRAFFIC_CTRL_CMD" << ": " <<
      int_to_hex(hafu->read64(TRAFFIC_CTRL_CMD)) << std::endl;
    os << "0x40038 " << std::setw(21) << "TRAFFIC_CTRL_DATA" << ": " <<
      int_to_hex(hafu->read64(TRAFFIC_CTRL_DATA)) << std::endl;
    os << "0x40040 " << std::setw(21) << "TRAFFIC_CTRL_PORT_SEL" << ": " <<
      int_to_hex(hafu->read64(TRAFFIC_CTRL_PORT_SEL)) << std::endl;
    os << "0x40048 " << std::setw(21) << "AFU_SCRATCHPAD" << ": " <<
      int_to_hex(hafu->read64(AFU_SCRATCHPAD)) << std::endl;
    
    os << std::endl;

    os << "0x1000 " << std::setw(22) << "scratch" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_SCRATCH)) << std::endl;
    os << "0x1001 " << std::setw(22) << "block_ID" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_BLOCK_ID)) << std::endl;
    os << "0x1008 " << std::setw(22) << "pkt_size" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_PKT_SIZE)) << std::endl;
    os << "0x1009 " << std::setw(22) << "ctrl0" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_CTRL0)) << std::endl;
    os << "0x1010 " << std::setw(22) << "ctrl1" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_CTRL1)) << std::endl;
    os << "0x1011 " << std::setw(22) << "dst_addr_lo" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_DST_ADDR_LO)) << std::endl;
    os << "0x1012 " << std::setw(22) << "dst_addr_hi" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_DST_ADDR_HI)) << std::endl;
    os << "0x1013 " << std::setw(22) << "src_addr_lo" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_SRC_ADDR_LO)) << std::endl;
    os << "0x1014 " << std::setw(22) << "src_addr_hi" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_SRC_ADDR_HI)) << std::endl;
    os << "0x1015 " << std::setw(22) << "rx_count" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_RX_COUNT)) << std::endl;
    os << "0x1016 " << std::setw(22) << "mlb_rst" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_MLB_RST)) << std::endl;
    os << "0x1017 " << std::setw(22) << "tx_count" << ": " <<
      int_to_hex(hafu->mbox_read(CSR_TX_COUNT)) << std::endl;

    return os;
  }

protected:
  uint32_t port_;
  std::string eth_loopback_;
  uint32_t num_packets_;
  std::string gap_;
  std::string pattern_;
  std::string src_addr_;
  std::string dest_addr_;
  std::string eth_ifc_;
  uint32_t start_size_;
  uint32_t end_size_;
  std::string end_select_;
};
