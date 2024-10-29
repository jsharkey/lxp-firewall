#
# Copyright (C) 2024 Jeff Sharkey, http://jsharkey.org/
# All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import re
import unittest

# These tests emulate netfilter to validate our bit-banging rules
# against real-world packets captured from an EG4 18kPV-12LV

# Packet format helpfully documented by
# https://github.com/celsworth/lxp-bridge/wiki/TCP-Packet-Spec
# and EG4-18KPV-12LV-Modbus-Protocol.pdf


with open("10-lxp.nft") as f:
    RULES = [ line for line in f.readlines() if "@ih" in line ]


def nf_eval_single(payload, rule):
    for clause in rule.split("@")[1:]:
        clause = re.split("[, ]", clause.strip())
        start = int(int(clause[1]) / 8)
        length = int(int(clause[2]) / 8)
        value = int(clause[3], 16)
        if int.from_bytes(payload[start:start+length]) != value:
            return False
    return True

def nf_eval(payload):
    payload = bytes.fromhex(payload)
    for rule in RULES:
        if nf_eval_single(payload, rule):
            return True
    return False

def firewall_eval(payload):
    return nf_eval(payload)


class FirewallTest(unittest.TestCase):
    def test_ping(self):
        self.assertTrue(firewall_eval("a11a05000d0001c1eeeeeeeeeeeeeeeeeeee00"))

    def test_params(self):
        self.assertFalse(firewall_eval("a11a05000d0001c3eeeeeeeeeeeeeeeeeeee00"))
        self.assertFalse(firewall_eval("a11a05000d0001c4eeeeeeeeeeeeeeeeeeee00"))

    def test_unknown(self):
        self.assertFalse(firewall_eval("a11a05000d0001dd"))

    def test_modbus_read_hold(self):
        self.assertTrue(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee12000003eeeeeeeeeeeeeeeeeeee00007f003bd6"))
        self.assertTrue(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee12000003eeeeeeeeeeeeeeeeeeee7f007f002202"))
        self.assertTrue(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee12000003eeeeeeeeeeeeeeeeeeee5000280014e6"))
        self.assertTrue(firewall_eval("a11a05001d0101c2eeeeeeeeeeeeeeeeeeee0f010103eeeeeeeeeeeeeeeeeeee0000fec2820900eeeeeeeeeeeeeeeeeeee46414142031b1c010100180a1b0a312f01000100000000002c000700d5eb78052c012c019808d8093e177a174008500a32081205b004400bc6000d003804a40b0f000f00500ada16e81740728677121638180d000d00e0150019a5032a042c003009a0089009200a000064006400e803e80364006400780064000f0010000000000000000000780064000000173b000000000000000078001400000000000000000000000000f0003c00000000000000000005000000000026029001fa00fa00780000000a0038ff2602000090012004000001000101000074176400ceff90010a000000000000000000a0180a00000064d5"))
        self.assertTrue(firewall_eval("a11a05001d0101c2eeeeeeeeeeeeeeeeeeee0f010103eeeeeeeeeeeeeeeeeeee7f00fe00000000000000000000000000006c174016140034000000000000000000000000001c020000000000000000000000000000000000000000000000000000900130020500000000000000000000000000000000009001000000000000000000000000f00078000000c0106400f009500a0a00140060092c0100002c0000003200640064001400900130020a0064003c0000000000300290010200fa00000000006400080210001500000000001c02e0015a003c0005003200080232005a00f4011c020c01000000006500530200000000000000000000000000000000000000000000000001002c010000ff000002000000000000000000000000000000008548"))
        self.assertTrue(firewall_eval("a11a05006f0001c2eeeeeeeeeeeeeeeeeeee61000103eeeeeeeeeeeeeeeeeeee5000500000000078001400000000000000000000000000f0003c00000000000000000005000000000026029001fa00fa00780000000a0038ff2602000090012004000001000101000074176400ceff90010a001924"))

    def test_modbus_read_input(self):
        self.assertTrue(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee120000040000000000000000000000007f009ac3"))
        self.assertTrue(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee12000004000000000000000000007f007f008317"))
        self.assertTrue(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee1200000400000000000000000000fe007f00ab2b"))
        self.assertTrue(firewall_eval("a11a05001d0101c2eeeeeeeeeeeeeeeeeeee0f010104eeeeeeeeeeeeeeeeeeee0000fe0c003c0f390f710f260264640027bc026002ef0200000000ba09010132006e17ac0700004803e803b609c4aa0a306e170000000036070000a200aa00b300de010000140000000000b80122009e0f450d543c0000f33c0000e43e0000c8ac0000110000008e0f0000be0b00006801000046950000d0190000000000000000000029002b0030000a000000e6db7c000000000000000000000000000000010001000200c800a00f3002c20100000000000000000000c0000000000000000000030002003002f7ff00000000b20d5e0dc800be000000230030028f0100000000000000000501b600eeeeeeeeeeeeeeeeeeeec20700000000000000000000000047f2"))
        self.assertTrue(firewall_eval("a11a05001d0101c2eeeeeeeeeeeeeeeeeeee0f010104eeeeeeeeeeeeeeeeeeee7f00fed104ce0400000000000000000000000068010000680100005f02cc04cd044c002d036404042d406600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0004700633200000000000000000000000000000000000000000000000000002c0100002c0000003200640064001400900130020a0064003c0000000000300290010200fa00000000006400080210001500000000001c02e0015a003c0005003200080232005a00f4011c020c01000000006500530200000000000000000000000000000000000000000000000001002c010000ff00000200000000000000000000000000000000571e"))
        self.assertTrue(firewall_eval("a11a05001d0101c2eeeeeeeeeeeeeeeeeeee0f010104eeeeeeeeeeeeeeeeeeeefe00fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000901c"))

    def test_modbus_write_single(self):
        self.assertFalse(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee12000006eeeeeeeeeeeeeeeeeeee77001400ca51"))
        self.assertFalse(firewall_eval("a11a0500200001c2eeeeeeeeeeeeeeeeeeee12000106eeeeeeeeeeeeeeeeeeee770014000bc1"))

    def test_modbus_write_multi(self):
        self.assertFalse(firewall_eval("a11a0100270001c2eeeeeeeeeeeeeeeeeeee19000010eeeeeeeeeeeeeeeeeeeedddd030006180a1b1108099841"))

    def test_modbus_write_date(self):
        self.assertTrue(firewall_eval("a11a0100270001c2eeeeeeeeeeeeeeeeeeee19000010eeeeeeeeeeeeeeeeeeee0c00030006180a1b1108099841"))
        self.assertTrue(firewall_eval("a11a0500200001c2eeeeeeeeeeeeeeeeeeee12000110eeeeeeeeeeeeeeeeeeee0c0003008adb"))

    def test_modbus_unknown(self):
        self.assertFalse(firewall_eval("a11a0100200001c2eeeeeeeeeeeeeeeeeeee120000ddeeeeeeeeeeeeeeeeeeee77001400ca51"))


if __name__ == '__main__':
    unittest.main()

