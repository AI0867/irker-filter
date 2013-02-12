
# For python >= 3.3, there's ipaddress
class CIDR(object):
    def __new__(cls, str_addr):
        if ":" in str_addr:
            return object.__new__(CIDRv6, str_addr)
        else:
            return object.__new__(CIDRv4, str_addr)
    def __init__(self, str_addr):
        if "/" in str_addr:
            self.str_addr, bits = str_addr.split("/")
            self.bits = int(bits)
        else:
            self.str_addr = str_addr
            self.bits = self.MAX_BITS
    def mask(self, addr):
        return addr & ((2**self.bits - 1) << (self.MAX_BITS - self.bits))
    def __contains__(self, other):
        try:
            return self.VERSION == other.VERSION and self.mask(other.addr) == self.addr
        except:
            return False
    def format(self, sep, bitgroup, base):
        assert (self.MAX_BITS % bitgroup) == 0
        steps = self.MAX_BITS / bitgroup
        try:
            spec = {2:"{0:b}", 8:"{0:o}", 10:"{0:d}", 16:"{0:X}"}[base]
        except KeyError:
            raise ValueError("Unusable base")

        addr = self.addr
        out = spec.format(addr % 2**bitgroup)
        for i in range(steps - 1):
            addr >>= bitgroup
            out = "{0}{1}{2}".format(spec.format(addr % 2**bitgroup), sep, out)

        return "{0}/{1}".format(out, self.bits)

class CIDRv4(CIDR):
    MAX_BITS = 32
    VERSION = 4
    def __init__(self, str_addr):
        CIDR.__init__(self, str_addr)

        addr_parts = self.str_addr.split(".")
        assert len(addr_parts) == 4
        addr = 0
        for part in addr_parts:
            addr *= 2**8
            addr += int(part)
        self.addr = self.mask(addr)
    def __str__(self):
        return self.format(".", 8, 10)

class CIDRv6(CIDR):
    MAX_BITS = 128
    VERSION = 6
    def __init__(self, str_addr):
        CIDR.__init__(self, str_addr)

        assert 0 < self.str_addr.count(":") < 8
        if self.str_addr.startswith(":"):
            self.str_addr = "0" + self.str_addr
        if "::" in self.str_addr:
            parts_missing = 8 - self.str_addr.count(":")
            self.str_addr = self.str_addr.replace("::", ":{0}".format("0:" * parts_missing))
        addr_parts = self.str_addr.split(":")
        assert len(addr_parts) == 8

        addr = 0
        for part in addr_parts:
            addr *= 2**16
            addr += int(part, 16)
        self.addr = self.mask(addr)
    def __str__(self):
        return self.format(":", 16, 16)

