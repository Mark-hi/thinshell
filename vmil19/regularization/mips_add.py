from bitstring import Bits

from vexshape import ShapeAnalysis
from senslist import SensitivityList
import bit_iter


# MIPS add
#                      RS       RT      RD
#spec = ['000000',  '000',2,  '000',2,  '1',4,   '00000100000']
spec = ['000000',  5,  5,  5,   '00000100000']
#import pudb ; pu.db

if __name__ == '__main__':
    anal = ShapeAnalysis(spec, 'mips')
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

    print("=========================")
    print("Shape partitioning:")
    print(anal.phase2_partitioning())

    print("===== SHAPES: ===========")
    for shapeN in range(len(anal.shapes)):
        print("=== Shape %d: ===========" % shapeN)
        print(anal.shapes[shapeN])
        print("ops = ")
        exampleOps = anal.specimenOpsOfShape(shapeN)
        ops = [anal.formulaFor(opNum, shapeN) for opNum in range(len(exampleOps))]
        print(ops)
