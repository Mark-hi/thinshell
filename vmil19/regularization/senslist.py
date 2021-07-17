from bitstring import Bits
from itertools import product
from z3 import *

import bit_iter

def bool2bv(b):
    return If(b, BitVecVal(1,1), BitVecVal(0,1))

def bools2bv(bs):
    bits = [bool2bv(b) for b in bs]
    return Concat(*bits)

def bitsExcept(bv, j):
    # bv with j-th bit removed
    # j=0 is LSB
    # result.size() = bv.size()-1
    if j==0:
        return Extract(bv.size()-1, 1, bv)
    if j==bv.size()-1:
        return Extract(bv.size()-2, 0, bv)
    hi = Extract(bv.size()-1, j+1, bv)
    lo = Extract(j-1, 0, bv)
    return Concat(hi, lo)


class SensitivityList:
    def __init__(self, width):
        # 'x': irrelevant
        # '!': significant
        # '?': unknown
        self.slist = ['?']*width

    def __repr__(self):
        return '\xAB'+''.join(list(reversed(self.slist)))+'\xBB'

    def probeIrrelevant(self, bitPosition):
        width = len(self.slist)
        v1 = BitVec('v1', width)
        v2 = BitVec('v2', width)
        j1 = bitsExcept(v1, bitPosition)
        j2 = bitsExcept(v2, bitPosition)
        thm = Implies(self.P[v1] != self.P[v2],
                      j1 != j2)
        self.solver.push()
        self.solver.add(Not(thm))
        irrel = self.solver.check() == unsat
        self.solver.pop()
        return irrel

    def guess(self, p):
        width = len(self.slist)
        self.solver = Solver()
        self.P = Array('P', BitVecSort(width), IntSort())
        for i in range(2**width):
            x = BitVecVal(i, width)
            y = p[i]
            self.solver.add(self.P[x] == IntVal(y))
        self.guess1()
        self.solver = None
        return self

    def guess1(self):
        try:
            i = self.slist.index('?')
        except ValueError:
            return self
        x = self.probeIrrelevant(i)
        self.slist[i] = 'x' if x else '!'
        return self.guess1()

    def slLetter_to_FieldSpecElement(self, i_l):
        index, letter = i_l
        if letter=='!':
            return 1 # a variable bit
        if letter=='x':
            return '0'
        error("cant have unknown sensitivity this late")

    def f(self):
        return lambda i_l: self.slLetter_to_FieldSpecElement(i_l)

    def asFieldSpec(self):
        l = list(map(self.f(), enumerate(self.slist)))
        #l = list(map(slLetter_to_FieldSpecElement, self.slist))
        l.reverse()
        return l

    def filterRelevantMembers(self, aList):
        z = list(zip(reversed(self.slist), aList))
        relevantElems = filter((lambda rel_bit: rel_bit[0]=='!'), z)
        snd = lambda a: a[1]
        return list(map(snd, relevantElems))

    def significantSlice(self, bits):
        return Bits(self.filterRelevantMembers(bits))

    @property
    def entropy(self):
        return len(list(filter(lambda x: x=='!', self.slist)))

    def isInsensitive(self):
        return self.entropy==0

    def twoPoints(self):
        if self.isInsensitive():
            raise Error()
        fff = self.asFieldSpec()
        # WRONG!!! needs to account for constructiveMask!
        itf = bit_iter.encodingspec_to_iter(fff)
        onePoint = next(itf)
        anotherPoint=next(itf)
        oneX = self.significantSlice(onePoint).uint
        anotherX = self.significantSlice(anotherPoint).uint
        oneY = proj[onePoint.uint]                                                                                                                            
