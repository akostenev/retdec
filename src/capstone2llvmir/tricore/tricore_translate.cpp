#include "retdec/capstone2llvmir/tricore/tricore.h"

#include <iostream>

namespace retdec {
namespace capstone2llvmir {
	
	
	
	
	




void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, llvm::IRBuilder<>& irb) {
	cs_tricore mi;
	
	if (i->id == 0x1d) {
		mi.op_count = 1;
		
		cs_tricore_op o;
		o.type = TRICORE_OP_IMM;
		
		//31		16 15			8 7		0
		//disp24[15:0]		disp24[23:16]		1DH
		o.imm = i->bytes[2] | i->bytes[3] << 8 | i->bytes[1] << 16;;
		
		mi.operands[0] = o;
	}
	
	
	
	op0 = loadOpUnary(&mi, irb);
	generateBranchFunctionCall(irb, op0);
	std::cout << "TRANSLATE JUMP " << std::endl;
}

} // namespace capstone2llvmir
} // namespace retdec