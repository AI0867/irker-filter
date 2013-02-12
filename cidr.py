
# For python >= 3.3, there's ipaddress
class CIDR(object):
    def __new__(cls, str_addr):
        if ":" in str_addr:
            return object.__new__(CIDRv6, str_addr)
        else:
            return object.__new__(CIDRv4, str_addr)
    def __init__(self, str_addr, sep, bitgroup, base):
        if "/" in str_addr:
            self.str_addr, bits = str_addr.split("/")
            self.bits = int(bits)
        else:
            self.str_addr = str_addr
            self.bits = self.MAX_BITS

        addr_parts = self.str_addr.split(sep)
        assert (self.MAX_BITS % bitgroup) == 0
        assert len(addr_parts) == (self.MAX_BITS / bitgroup)

        addr = 0
        for part in addr_parts:
            addr *= 2**bitgroup
            addr += int(part, base)
        self.addr = self.mask(addr)
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
        CIDR.__init__(self, str_addr, ".", 8, 10)
    def __str__(self):
        return self.format(".", 8, 10)

class CIDRv6(CIDR):
    MAX_BITS = 128
    VERSION = 6
    def __init__(self, str_addr):
        assert 1 < self.str_addr.count(":") < 8
        if str_addr.startswith(":"):
            str_addr = "0" + str_addr
        if "::" in str_addr:
            parts_missing = 8 - str_addr.count(":")
            str_addr = str_addr.replace("::", ":{0}".format("0:" * parts_missing))

        CIDR.__init__(self, str_addr, ":", 16, 16)
    def __str__(self):
        return self.format(":", 16, 16)

