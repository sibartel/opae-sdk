#! /usr/bin/env python3
# Copyright(c) 2021, Intel Corporation
#
# Redistribution  and  use  in source  and  binary  forms,  with  or  without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of  source code  must retain the  above copyright notice,
#  this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name  of Intel Corporation  nor the names of its contributors
#   may be used to  endorse or promote  products derived  from this  software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,  BUT NOT LIMITED TO,  THE
# IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT  SHALL THE COPYRIGHT OWNER  OR CONTRIBUTORS BE
# LIABLE  FOR  ANY  DIRECT,  INDIRECT,  INCIDENTAL,  SPECIAL,  EXEMPLARY,  OR
# CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT LIMITED  TO,  PROCUREMENT  OF
# SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE,  DATA, OR PROFITS;  OR BUSINESS
# INTERRUPTION)  HOWEVER CAUSED  AND ON ANY THEORY  OF LIABILITY,  WHETHER IN
# CONTRACT,  STRICT LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE  OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,  EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import re
import os
import glob
import argparse
import sys
import traceback
import fcntl
import stat
import struct
import mmap
from ethernet.hssicommon import *


ETH_10G = 0x10000
ETH_25G = 0x20000
ETH_100G = 0x40000
ETH_4x25G = 0x80000
ETH_PORT = ETH_10G | ETH_25G | ETH_100G |ETH_4x25G
CPRI_24G = 0x100000
CPRI_12G = 0x200000
CPRI_10G = 0x400000
CPRI_9p8G = 0x800000
CPRI_4p9G = 0x1000000
CPRI_2p4G = 0x2000000
CPRI_PORT = CPRI_24G | CPRI_12G | CPRI_10G | CPRI_9p8G | CPRI_4p9G | CPRI_2p4G

ETH_RSFEC = 0x1
ETH_PTP = 0x100


HSSI_DR_GROUPS = {0: {0: ETH_25G | ETH_RSFEC,
                      1: ETH_25G,
                      2: ETH_10G},
                  1: {0: ETH_25G | ETH_PTP | ETH_RSFEC,
                      1: ETH_25G | ETH_PTP,
                      2: ETH_10G | ETH_PTP,
                      3: CPRI_24G,
                      4: CPRI_12G,
                      5: CPRI_10G,
                      6: CPRI_9p8G,
                      7: CPRI_4p9G,
                      8: CPRI_2p4G},
                  2: {},
                  3: {0: ETH_100G | ETH_RSFEC,
                      1: ETH_100G,
                      2: ETH_4x25G | ETH_RSFEC,
                      3: ETH_4x25G}}


class FPGAHSSIFEC(HSSICOMMON):
    def __init__(self, args):
        self._mode = args.mode
        self._hssi_grps = args.hssi_grps
        self._pcie_address = args.pcie_address
        self._port = args.port
        HSSICOMMON.__init__(self)

    def hssi_profile_op(self, profile=None):
        self.open(self._hssi_grps[0][0])

        hssi_feature_list = hssi_feature(self.read32(0, 0xC))
        if (self._port >= hssi_feature_list.num_hssi_ports):
            print("Invalid Input port number")
            self.close()
            return -1

        cmd_sts = hssi_cmd_sts(0)
        ctl_addr = hssi_ctl_addr(0)
        if not profile:
            ctl_addr.sal_cmd = HSSI_SALCMD.GET_HSSI_PROFILE.value
            cmd_sts.read = 1
        else:
            ctl_addr.sal_cmd = HSSI_SALCMD.SET_HSSI_PROFILE.value
            cmd_sts.write = 1

        # set port number
        ctl_addr.port_address = self._port

        ret = self.clear_ctl_sts_reg(0)
        if not ret:
            print("Failed to clear HSSI CTL STS csr")
            self.close()
            return -1

        self.write32(0, HSSI_CSR.HSSI_CTL_ADDRESS.value, ctl_addr.value)
        self.write32(0, HSSI_CSR.HSSI_CTL_STS.value, cmd_sts.value)

        if not self.read_poll_timeout(0,
                                      HSSI_CSR.HSSI_CTL_STS.value,
                                      0x2):
            print("HSSI ctl sts csr fails to update ACK")
            self.close()
            return -1

        ret = self.clear_ctl_sts_reg(0)
        if not ret:
            print("Failed to clear HSSI CTL STS csr")
            self.close()
            return -1

        if not profile:
            profile = self.read32(0, HSSI_CSR.HSSI_RD_DATA.value)

        self.close()

        return profile

    def hssi_set_mode(self):
        """
        set fec mode
        """

        self.hssi_info(self._hssi_grps[0][0])

        profile = self.hssi_profile_op()
        if profile < 0:
            print("failed to get hssi profile")
            return -1

        group = (profile >> 4) & 0x7
        dr_group = HSSI_DR_GROUPS.get(group, {})
        coding = profile & 0xf
        if len(dr_group) == 0:
            print("unknown profile {}:{}".format(group, coding))
            return -1
        if not coding in dr_group:
            print("unknown profile {}:{}".format(group, coding))
            return -1

        if (dr_group[coding] & ETH_PORT) == 0:
            print("Not ethernet protocol")
            return -1

        if dr_group[coding] & ETH_10G:
            print("10G ethernet port do not support FEC")
            return -1

        if (self._mode == 'rs') and (dr_group[coding] & ETH_RSFEC):
            return 0
        if (self._mode == 'no') and (dr_group[coding] & ETH_RSFEC) == 0:
            return 0

        if self._mode == 'no':
            coding &= ~ETH_RSFEC
        elif self._mode == 'rs':
            coding |= ETH_RSFEC
        else:
            print("unsupported FEC mode '{}'".format(self._mode))
            return -1

        profile = (group << 4) | coding;
        self.hssi_profile_op(profile)

        return 0

    def hssi_get_mode(self):
        """
        get fec mode
        """

        self.hssi_info(self._hssi_grps[0][0])

        profile = self.hssi_profile_op()
        if profile < 0:
            print("failed to get hssi profile")
            return None

        group = (profile >> 4) & 0x7
        dr_group = HSSI_DR_GROUPS.get(group, {})
        coding = profile & 0xf
        if len(dr_group) == 0:
            print("unknown profile {}:{}".format(group, coding))
            return None
        if not coding in dr_group:
            print("unknown profile {}:{}".format(group, coding))
            return None

        if (dr_group[coding] & ETH_PORT) == 0:
            print("Not ethernet protocol")
            return None

        if dr_group[coding] & ETH_RSFEC:
            return 'rs'
        else:
            return 'no'


def main():
    """
    parse input arguments pciaddress and port
    enum fpga pcie devices and find match
    set fec mode
    """

    parser = argparse.ArgumentParser()
    pcieaddress_help = 'sbdf of device to program (e.g. 0000:04:00.0).' \
                       ' Optional when one device in system.'
    parser.add_argument('--pcie-address', '-P',
                        default=None, help=pcieaddress_help)
    parser.add_argument('--port', type=int,
                        default=0, help='hssi port number')
    parser.add_argument('--mode', choices=['no', 'rs'], nargs='?',
                        default=None, help='Choose fec mode to configure')

    args, left = parser.parse_known_args()

    print("pcie_address:", args.pcie_address)
    print("args.port:", args.port)
    print("args.mode:", args.mode)

    if not veriy_pcie_address(args.pcie_address):
        sys.exit(1)

    f = FpgaFinder(args.pcie_address)
    devs = f.enum()
    for d in devs:
        print('sbdf: {segment:04x}:{bus:02x}:{dev:02x}.{func:x}'.format(**d))
        print('FPGA dev:', d)
    if len(devs) > 1:
        print('{} FPGAs are found\nplease choose one FPGA'.format(len(devs)))
        sys.exit(1)
    if not devs:
        print('no FPGA found')
        sys.exit(1)

    args.hssi_grps = f.find_hssi_group(devs[0].get('pcie_address'))
    if len(args.hssi_grps) == 0:
        print("Failed to find HSSI feature", devs[0].get('pcie_address'))
        sys.exit(1)

    print('HSSI UIO dev: {}'.format(args.hssi_grps[0][0]))

    fec = FPGAHSSIFEC(args)
    if not args.mode:
        print('Current FEC mode is {}'.format(fec.hssi_get_mode()))
        sys.exit(0)
    else:
        print('Set FEC mode to {}'.format(args.mode))
        sys.exit(fec.hssi_set_mode())


if __name__ == "__main__":
    main()
