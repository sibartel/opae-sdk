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
import struct
from ethernet.hssicommon import *


class FPGAHSSIMAC(HSSICOMMON):
    def __init__(self, args):
        self._hssi_grps = args.hssi_grps
        self._pcie_address = args.pcie_address
        self._port = args.port
        HSSICOMMON.__init__(self)

    def get_mac_mtu(self):
        """
        clear ctl address and ctl sts CSR
        write 0x4 value ctl address csr
        write 0x1 value ctl sts csr
        poll for status
        HSSI Read Data CSR [31:16] Maximum TX frame size
        HSSI Read Data CSR [15:0] Maximum Rx frame size
        """
        self.open(self._hssi_grps[0][0])

        hssi_feature_list = hssi_feature(self.read32(0, 0xC))
        if self._port >= HSSI_PORT_COUNT:
            print("Invalid input port number")
            self.close()
            return False

        enable = self.register_field_get(hssi_feature_list.port_enable,
                                         self._port)

        if enable == 0:
            print("Input port is not enabled or active")
            self.close()
            return False

        ctl_addr = hssi_ctl_addr(0)
        ctl_addr.sal_cmd = HSSI_SALCMD.GET_MTU.value
        # set port number
        ctl_addr.port_address = self._port

        res, value = self.read_reg(0, ctl_addr.value)
        if not res:
            self.close()
            print("Failed to read mtu")
            return False

        mask = 0
        width = 16
        for x in range(width):
            mask |= (1 << x)
        #HSSI Read Data CSR [15:0] Maximum Rx frame size
        print("Port{0} Maximum RX frame size:{1}".format(self._port,
                                                         value & mask))
        #HSSI Read Data CSR [31:16] Maximum Tx frame size
        print("Port{0} Maximum TX frame size:{1}".format(self._port,
                                                         value >> width))

        self.close()
        return True

    def hssi_mtu_start(self):
        """
        print hssi info
        get mtu
        """
        if not self.hssi_info(self._hssi_grps[0][0]):
            print("Failed to read hssi information")
            sys.exit(1)
        if not self.get_mac_mtu():
            print("Failed to mtu information")
            sys.exit(1)


def main():
    """
    parse input arguemnts pciaddress and mtu
    enum fpga pcie devices and find match
    read hssi mtu
    """
    parser = argparse.ArgumentParser()

    pcieaddress_help = 'sbdf of device to program \
                        (e.g. 0000:04:00.0).' \
                       ' Optional when one device in system.'
    parser.add_argument('--pcie-address', '-P',
                        default=None, help=pcieaddress_help,
                        required=True)

    parser.add_argument('--port', type=int,
                        default=0,
                        help='hssi port number')

    # exit if no commad line argument
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args, left = parser.parse_known_args()

    print(args)
    if not verify_pcie_address(args.pcie_address.lower()):
        sys.exit(1)

    f = FpgaFinder(args.pcie_address.lower())
    devs = f.enum()
    for d in devs:
        print('sbdf: {segment:04x}:{bus:02x}:{dev:02x}.{func:x}'.format(**d))
        print('FPGA dev:', d)
    if len(devs) > 1:
        print('{} FPGAs are found\nplease choose '
              'one FPGA'.format(len(devs)))
        sys.exit(1)
    if not devs:
        print('no FPGA found')
        sys.exit(1)

    args.hssi_grps = f.find_hssi_group(devs[0].get('pcie_address'))
    print("args.hssi_grps{}".format(args.hssi_grps))
    if len(args.hssi_grps) == 0:
        print("Failed to find HSSI feature{}".format(devs[0].get('pcie_address')))
        sys.exit(1)

    print("fpga uio dev:{}".format(args.hssi_grps[0][0]))

    lp = FPGAHSSIMAC(args)
    lp.hssi_mtu_start()


if __name__ == "__main__":
    main()
