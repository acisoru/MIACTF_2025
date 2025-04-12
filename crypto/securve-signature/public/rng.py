import secrets

class SplitMix64:
    def __init__(self, state=None):
        if state is None:
            state = secrets.randbits(64)
        self.state = state

    def next(self):
        self.state += 0x9e3779b97f4a7c15
        self.state %= 2 ** 64
        result = self.state
        result = (result ^ (result >> 30)) * 0xbf58476d1ce4e5b9 % 2 ** 64
        result = (result ^ (result >> 27)) * 0x94d049bb133111eb % 2 ** 64
        return result ^ (result >> 31)
    
    def jump(self, n):
        self.state += 0x9e3779b97f4a7c15 * n
        self.state %= 2 ** 64

    def randbelow(self, bound):
        r = 0
        for _ in range((bound.bit_length() + 63) // 64):
            r <<= 64
            r |= self.next()
        return r % bound

