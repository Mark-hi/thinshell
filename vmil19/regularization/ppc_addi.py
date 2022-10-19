from bitstring import Bits

from vexshape import ShapeAnalysis
from senslist import SensitivityList
import bit_iter

class OperandProjection:
    def __init__(self, OPS, opIndex):
        self.OPS = OPS
        self.opIndex = opIndex

    def __getitem__(self, k):
        ops = self.OPS[k]
        return ops[self.opIndex]


# addis/lis
#          op       RT    RA       d
spec = ['001111', '00011', 5,   '00000000',8]
#spec = ['001111',   5, '11100',   '00000000',8]
#spec = ['001111',  5, '00011', '1111000011110000']
#import pudb ; pu.db

def inferFormulaFor(opNum, shapeN):
    proj = OperandProjection(anal.OPS, opNum)
    sl = SensitivityList(anal.entropy)
    opSensitivity = sl.guess(proj)
    if opSensitivity.isInsensitive():
        theConst = proj[0]
        print(hex(theConst))
    else:
        # we found at least one sensitive bit, so at least 2 points.
        # at this point, we can't handle anything nonlinear.
        fff = opSensitivity.asFieldSpec()
        itf = bit_iter.encodingspec_to_iter(fff)
        onePoint = next(itf)
        anotherPoint=next(itf)
        oneX = opSensitivity.significantSlice(onePoint).uint
        anotherX = opSensitivity.significantSlice(anotherPoint).uint
        oneY = proj[onePoint.uint]
        anotherY = proj[anotherPoint.uint]
        if (anotherY-oneY)%(anotherX-oneX) != 0:
            nonlinear
        A = (anotherY-oneY)//(anotherX-oneX)
        if (anotherY+oneY-A*(anotherX+oneX))%2 != 0:
            nonlinear
        B = (anotherY+oneY-A*(anotherX+oneX))//2
        special('constant')

if __name__ == '__main__':
    anal = ShapeAnalysis(spec, 'powerpc')
    anal.phase0_VEX()
    print("Found %s shapes" % len(anal.shapes))
    exit()
    print(anal.sensitivity)
    print("Representative instances:")
    for specimen in anal.section:
        print(specimen)
    print("=========================")

    anal.phase1_shapes()
    print(anal.relevantBitPositionsString())
    for bits_shape in anal.shapeTags.items():
        print(bits_shape)
    print("or in the opposite direction:")
    print(anal.tagSets)

    import pudb ; pu.db
    anal.phase2_partitioning()
    if anal.isRegular():
        print("Instruction is REGULAR")
    else:
        print("Instruction is easily normalizable;")
        print("Narrow shape is %d" % anal.narrow)


# infer operand formulae for the narrow shape
    print("=== shape %d: ============" % anal.narrow)
    print(anal.shapes[anal.narrow]) # cant to better because it's a string
    print("=== operands: ===========")
    print(".......")



# infer operand formulae for the wide shape
    print("=== shape %d: ============" % anal.wide)
    print(anal.shapes[anal.wide]) # cant to better because it's a string
    print("=== operands: ===========")

# a representative instance to fetch from OPS
# this is only needed so that we know how many operands to iterate over
    wideSpecimen = anal.section[anal.wide]
    aaa = list(wideSpecimen).copy()
    aaa.reverse()
    b = Bits([aaa[k] for k in anal.varBitPositions])
    exampleOps = anal.OPS[b.uint]
#opNum proshpandulivae range(exampleOps.len())
    opNum = 2
    shapeN = anal.wide





    f = inferFormulaFor(opNum, shapeN)





