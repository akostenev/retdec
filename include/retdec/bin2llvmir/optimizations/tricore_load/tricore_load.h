#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_TRICORE_LOAD_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_TRICORE_LOAD_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class TricoreLoad : public llvm::ModulePass
{
        public:
                static char ID;
                TricoreLoad();
                virtual ~TricoreLoad();
                virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
                virtual bool runOnModule(llvm::Module& M) override;

        private:
                long unsigned int getValOnPos(long base, long disp, unsigned size = 4);

                Config* config = nullptr;
                std::ifstream Input;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
