# Here is a little experiment with vex regularization.

# In Pharo-ArchC and related fundamental parts of Smalltalk-25,
# we call things of the form (using PPC example here)
#    addis RT, RA, D
# "instruction declarations", and things of the form
#    addis r3, r1, 0x1234
# "ground instruction instances".
#
# We say that two VEX IRSBs have the same shape if they only differ
# in the leaf constants.  This means, the U16/U32/etc constants in Const
# expressions, but also things like register offsets in GET and PUT
# (because, say, when RA varies those will vary too).  This has the
# disadvantage that special offsets like PC=1168 on PPC, are not recognized
# as special; cf. criticism of ARM uniform SPRs in Waterman's thesis.
#
# Of course, two IRSBs of different shapes can still denote the same
# function; in this sense shape is not a hash for homotopy.
#
# An instruction is called vex-regular if all its ground instances
# lift to VEX of the same shape.


import pyvex
import archinfo
from z3 import *
from bit_iter import encodingspec_to_iter
from bitstring import Bits

from senslist import SensitivityList
from special_chars import *

# uncomment exactly one of the following two lines:
#from multiprocessing.pool import ThreadPool as Pool
from multiprocessing import Pool

class Empty:
    def size(self):
        return 0

def mingle(leftBV, rightBV, mask):
    if leftBV.size()+rightBV.size() != mask.length:
        raise Exception("wrong count of bits")
    if mask.length==0:
        return Empty()
    if mask[0]:
        sz = rightBV.size()
        leftmost = Extract(sz-1,sz-1, rightBV)
        rest = Extract(sz-2,0, rightBV) if sz>1 else Empty()
        newMask = mask[1:]
        tail = mingle(leftBV, rest, newMask)
        if tail.size()==0:
            return leftmost
        return simplify(Concat(leftmost, tail))
    else:
        sz = leftBV.size()
        leftmost = Extract(sz-1,sz-1, leftBV)
        rest = Extract(sz-2,0, leftBV) if sz>1 else Empty()
        newMask = mask[1:]
        tail = mingle(rest, rightBV, newMask)
        if tail.size()==0:
            return leftmost
        return simplify(Concat(leftmost, tail))

class OperandProjection:
    def __init__(self, OPS, SHAPES, correctShape, opIndex):
        self.OPS = OPS
        self.SHAPES = SHAPES
        self.correctShape = correctShape
        self.opIndex = opIndex

    def __getitem__(self, k):
        if self.SHAPES[k] != self.correctShape:
            return -1 #need something to construct a Z3 int
        ops = self.OPS[k]
        return ops[self.opIndex]

def termConstants(irNode):
    name = irNode.__class__.__name__
    return getattr(ConstExtractor(), name) (irNode)

class ConstExtractor:
    def IMark(self, irNode):
        return [irNode.addr, irNode.len, irNode.delta]

    def WrTmp(self, irNode):
        return (termConstants(irNode.data))

    def Put(self, irNode):
        return irNode.offset

    def Get(self, irNode):
        return irNode.offset

    def Binop(self, irNode):
        evenNones = [termConstants(arg) for arg in irNode.args]
        return [x for x in evenNones if x!=None]

    def Unop(self, irNode):
        evenNones = [termConstants(arg) for arg in irNode.args]
        return [x for x in evenNones if x!=None]

    def RdTmp(self, irNode):
        return []

    def Const(self, irNode):
        return termConstants(irNode.con)
    
    def U32(self, irNode):
        return irNode.value
    
    def Exit(self, irNode):
        return 7777777 # BOGUS -- please implement


def termShape(irNode):
    name = irNode.__class__.__name__
    return getattr(ShapeDeterminant(), name) (irNode)

class ShapeDeterminant:
    def IMark(self, irNode):
        return ('IMark', CenteredDot, CenteredDot, CenteredDot)

    def WrTmp(self, irNode):
        return ('WrTmp', irNode.tmp, termShape(irNode.data))

    def Put(self, irNode):
        return ('Put', CenteredDot, termShape(irNode.data))

    def Get(self, irNode):
        return ('Get', irNode.ty, CenteredDot)

    def Binop(self, irNode):
        opArgs = [termShape(arg) for arg in irNode.args]
        return tuple(['Binop', irNode.op]+opArgs)

    def Unop(self, irNode):
        opArgs = [termShape(arg) for arg in irNode.args]
        return tuple(['Unop', irNode.op]+opArgs)

    def RdTmp(self, irNode):
        return ('RdTmp', irNode.tmp)

    def Const(self, irNode):
        return ('Const', termShape(irNode.con))
    
    def U32(self, irNode):
        return ('U32', CenteredDot)

    def Exit(self, irNode):
        guard = termShape(irNode.guard)
        dst = termShape(irNode.dst)
        return ('Exit', guard, dst, irNode.jk, CenteredDot)

def flatten(l):
    out = []
    for item in l:
        if isinstance(item, (list, tuple)):
            out.extend(flatten(item))
        else:
            out.append(item)
    return out

def vexSignature(encoding, arch):
    irsb = pyvex.block.IRSB(encoding.bytes, 0x1000, arch, opt_level=-1)
    sig = [ termShape(t) for t in irsb.statements ]
    ops = [ termConstants(t) for t in irsb.statements ]
    return encoding, irsb.tyenv.types, sig, flatten(ops)

def findArchInfo(archName):
    if archName=='powerpc':
        return archinfo.ArchPPC32(archinfo.Endness.BE)
    if archName=='armv5':
        return archinfo.ArchARM()
    if archName=='mips':
        return archinfo.ArchMIPS32()
    if archName=='x86':
        return archinfo.ArchX86()
    raise NotFoundError(archName)

def varBitPositionsFrom(spec, soFar, msb):
    if not spec:
        return soFar
    car = spec[0]
    if isinstance(car, str):
        return varBitPositionsFrom(spec[1:], soFar, msb-len(car))
    l = [msb-pos for pos in range(car)]+soFar
    return varBitPositionsFrom(spec[1:], l, msb-car)


class ShapeAnalysis:
    def __init__(self, spec, archName):
        self.spec = spec
        self.arch = findArchInfo(archName)
        self.computeVarBitPositions()

    def phase0_VEX(self):
        '''Lift VEX IR for every instance and collect the results.'''
        self._sensitivity = None
        self.specimens = {}
        self.shapes = {}
        self.shapeIndices = {} #reverse of shapes
        self.P   = [None] * (2**self.entropy)
        self.OPS = [None] * (2**self.entropy)

        it = encodingspec_to_iter(self.spec)

        nworker = 4
        print("Creating pool with", nworker, "processes.")
        with Pool(processes = nworker) as pool:
            multiple_results = [pool.apply_async(vexSignature, (encoding, self.arch)) for encoding in it]
            k = 0
            l = 0
            for res in multiple_results:
                l = l + 1
                encoding,ty,sig,ops = res.get()
                thisSig = str((ty,sig))
                if thisSig not in self.specimens:
                    self.specimens[thisSig] = encoding
                    self.shapes[k] = thisSig
                    self.shapeIndices[thisSig] = k
                    k = k+1
                encodingInt = int(self.variableSlice(encoding), 2)
                self.P[encodingInt] = self.shapeIndices[thisSig]
                self.OPS[encodingInt] = ops
            print(l, "results processed.")

    def phase1_shapes(self):
        '''Group shapes'''
        self.shapeTags = {}
        self.tagSets = {k:set() for k in range(len(self.shapes))}
        fs = self.sensitivity.asFieldSpec()
        it = encodingspec_to_iter(fs)
        for varPossibility in it:
            sigBits = self.sensitivity.significantSlice(varPossibility)
            shapeNum = self.P[varPossibility.uint]
            self.shapeTags[sigBits] = shapeNum
            self.tagSets[shapeNum].add(sigBits)

    def factorize_flock(self, flocking):
        lBits = flocking.count(0)
        rBits = flocking.count(1)
        sh = Function('sh', BitVecSort(lBits), BitVecSort(rBits),  IntSort())
        f  = Function('f',  IntSort(),     BoolSort(),     IntSort())
        t  = Function('t',  BitVecSort(lBits),             IntSort())
        s  = Function('s',  BitVecSort(rBits),             BoolSort())

        solver = Solver()
        l = BitVec('l', lBits)
        r = BitVec('r', rBits)
        composition = ForAll([l,r], sh(l,r)==f(t(l),s(r)))
        solver.add(composition)

        for iy in range(2**lBits):
            for ix in range(2**rBits):
                x = BitVecVal(ix,rBits)
                y = BitVecVal(iy,lBits)
                yx = mingle(y,x, flocking)
                iyx = simplify(yx).as_long()
                byx = Bits(uint=iyx, length=lBits+rBits)
                shape = self.shapeTags[byx]
                solver.add(sh(y,x)==IntVal(shape))

        result = solver.check()
        if result != sat:
            return None
        m = solver.model()
        classifier = m[s]
        if classifier.num_entries() != 1:
            return None
        return classifier

    def find_flockings(self):
        e = self.sensitivity.entropy
        ran = range(1, 2**e-1)
        candidates = [Bits(uint=k, length=e) for k in ran]
        candidates.sort(key=lambda b: b.count(1))
        for flocking in candidates:
            f = self.factorize_flock(flocking)
            if f:
                yield (flocking, f)

    def phase2_partitioning(self):
        '''See if the partitioning of instances into shapes
        exhibits a simple structure.'''
        if self.isRegular():
            self.narrow = 0
            return "too easy: already regular"

        # We say an instruction is _easily normalizable_ if it
        # decomposes into exactly two shapes: the _narrow_ shape
        # with only one encoding of the discriminating bits,
        # and the _wide_ shape (everything else).
        # For example, addi has narrow RA=0 and wide RA!=0.
        # Obviously, when there is only one shape-discriminating
        # bit (e.g. H bit on ARM instruction b), both shapes can
        # be considered narrow.  In this case we arbitrarily choose
        # which side to call narrow/wide.
        # NB: not every two-shaped instruction (which we call _fork_)
        # is easily normalizable: the condition could be more complex
        # than "constant point/everything else)
        if self.isFork():
            return self.analyze_fork()
        # more than two shapes; can we factorize them in flocks?
        fl = self.find_flockings()
        # TODO: recursive flocks
        return list(fl)


    def specimenEncodingOfShape(self, shapeN):
        thisShapeSpecimen = self.section[shapeN]
        aaa = list(thisShapeSpecimen).copy()
        aaa.reverse()
        return Bits([aaa[k] for k in self.varBitPositions])

    def specimenOpsOfShape(self, shapeN):
        return self.OPS[self.specimenEncodingOfShape(shapeN).uint]

    def formulaFor(self, opNum, shapeN):
        proj = OperandProjection(self.OPS, self.P, shapeN, opNum)
        sl = SensitivityList(self.entropy)
        opSensitivity = sl.guess(proj, self.P, shapeN)
        if opSensitivity.isInsensitive(): # just a silly shortcut
            op = proj[self.specimenEncodingOfShape(shapeN).uint]
            return repr(opSensitivity), 0, op
        width = opSensitivity.entropy
        solver = Solver()
        Q = Array('Q', BitVecSort(width), BoolSort())
        Y = Array('Y', BitVecSort(width), IntSort())
        for i in range(2**width):
            x = BitVecVal(i, width)
            f = opSensitivity.fiber(i)
            ff = filter(lambda j: self.P[j]==shapeN, f)
            try:
                s = next(ff)
                y = proj[s]
                solver.add(Y[x] == IntVal(y))
            except StopIteration:
                pass
        a = Int('a')
        b = Int('b')
        x = BitVec('x', width)
        thm = ForAll(x,
            Y[x] == (BV2Int(x)*a + b))
        solver.add(thm)
        result = solver.check()
        if result != sat:
            raise Error()
        m = solver.model()
        return repr(opSensitivity), m.eval(a).as_long(), m.eval(b).as_long()


    def variableSlice(self, full):
        l = [('1' if full[31-i] else '0') for i in self.varBitPositions]
        return ''.join(l)

    def isRegular(self):
        return len(self.shapes)==1

    def isFork(self):
        return len(self.shapes)==2

    def phase2b_analyze_fork(self):
        if len(self.tagSets) != 2:
            raise Error("what?!!!")
        return "TODO: implement analyze_fork"

    def computeVarBitPositions(self):
        self.varBitPositions = varBitPositionsFrom(self.spec, [], 31)
        self.varBitPositions.sort()
        self.varBitPositions.reverse()
        self.entropy = len(self.varBitPositions)

    @property
    def section(self):
        return list(self.specimens.values())

    def computeSensitivity(self):
        sl = SensitivityList(self.entropy)
        self._sensitivity = sl.guess(self.P)

    @property
    def sensitivity(self):
        if not self._sensitivity:
            self.computeSensitivity()
        return self._sensitivity

    def relevantBitPositions(self):
        return self.sensitivity.filterRelevantMembers(self.varBitPositions)

    def relevantBitPositionsString(self):
        relevantOnes = self.relevantBitPositions()
        l = lambda pos: '!' if pos in relevantOnes else '.'
        return ''.join(map(l, range(31,-1,-1)))
