/**
* @file src/bin2llvmir/optimizations/tricore_load/tricore_load.cpp
* @brief Load simulator of TriCore aX Register.
*/

#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>

#include <map>
#include <vector>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/tricore_load/tricore_load.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/bin2llvmir/utils/instruction.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

char TricoreLoad::ID = 0;

static RegisterPass<TricoreLoad> X(
		"tricore-load",
		"TriCore load simulator",
		false, // Only looks at CFG
		false // Analysis Pass
);

TricoreLoad::TricoreLoad() :
		ModulePass(ID),
		Input("/home/zeus/dc/fw/DX55ZDCUJ0000.bin", std::ifstream::binary)
{

}

TricoreLoad::~TricoreLoad() {
    if (Input.is_open()) {
        Input.close();
    }
}


void TricoreLoad::getAnalysisUsage(AnalysisUsage &AU) const
{

}

/**
 * @return @c True if al least one instruction was (un)volatilized.
 *         @c False otherwise.
 */
bool TricoreLoad::runOnModule(Module& M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	auto a9On2088 = getValOnPos(0x8016D340, 2088, 4);
        std::cout << "Word on a9[2088]: " << std::hex << a9On2088 << std::endl;
        std::cout << "HWORD on a9[2088][2594]: " << std::hex << getValOnPos(a9On2088, 2594, 2) << std::endl;




//         Input.close();


//         Input.seekg()


// 	ReachingDefinitionsAnalysis RDA;
// 	RDA.runOnModule(M, config);

        /*
            %2 = load i32, i32* @a9, align 4
            %3 = add i32 %2, 2088
            %4 = inttoptr i32 %3 to i32*
            %5 = load i32, i32* %4, align 4
            store i32 %5, i32* @a2, align 4    --> a2 = a9[2088]

            /////////////////////////////
            %6 = load i8, i8* inttoptr (i32 -805300142 to i8*), align 2
            %7 = sext i8 %6 to i32
            store i32 %7, i32* @d0, align 4    --> d0 = word_D0001852
            /////////////////////////////

            %8 = load i32, i32* @a2, align 4
            %9 = add i32 %8, 2594
            store i32 %9, i32* @a15, align 4   --> a15 = a2[2594]

            %10 = load i32, i32* @a15, align 4
            %11 = inttoptr i32 %10 to i16*
            %12 = load i16, i16* %11, align 2
            %13 = sext i16 %12 to i32
            store i32 %13, i32* @d15, align 4  --> d15 = *a15

            1.    Find first dimension over: %2 = load i32, i32* @a9, align 4
            1.1   Save all disp=X a9[X]
            1.1   Save all store i32 %5, i32* @a2, align 4    --> a2 = a9[X]

            2.    Find second dimension over store i32 %9, i32* @a15, align 4 (anchor over @a2 to 1.1)
            2.1   Save all disp=Y a9[X][Y]
            2.2   Save all stores with a9[X][Y] : store i32 %9, i32* @a15, align 4
            2.2.1 Ignore all falsePositives reg, e.g. @a15 with @a15 = aZ[X][Y] with Z != 9

            3.    Find matching store i32 %13, i32* @d15, align 4, with value = a9[X][Y]
            3.1   Replace all uses of e.g. %13 with ConstantInt in binary, //TODO now ConstInt(0xF2D299), replace it with the original value in the binary
        */

        std::map<Instruction*, std::map<GlobalValue*, std::map<Instruction*, std::set<GlobalValue*>>>> a9; // a9[2088] -> a2, a2[2594]

        bool foundA9 = false;

	for (auto &F : M.getFunctionList())
	for (BasicBlock &B : F)
	for (Instruction &I : B)
	{
//             I.dump();

            if (LoadInst* l = dyn_cast<LoadInst>(&I)) {
                if (!foundA9 && l->getPointerOperand() == config->getLlvmRegister("a9")) { // %2 = load i32, i32* @a9, align 4
                    foundA9 = true;

                    std::cout << "Found A9, get all loadInst Users" << std::endl;
                    std::set<LoadInst*> a9Loads;
                    for (auto *U : l->getPointerOperand()->users()) {
                        if (LoadInst* a9Load = dyn_cast<LoadInst>(U)) {
//                             std::cout << "\t>" << std::flush; a9Load->dump();
                            a9Loads.insert(a9Load);
                        }
                    }

                    if (!a9Loads.empty()) {
                        std::cout << "\t getAll disp addIns for a9" << std::endl; // %3 = add i32 %2, 2088

                        for (auto* a9l : a9Loads) {
                            for (auto* U : a9l->users()) {

                                if (Instruction* addI = dyn_cast<Instruction>(U)) {
                                    if (addI->getOpcode() == Instruction::Add) {
//                                         std::cout << "\t\t>" << std::flush; addI->dump();
                                        a9.emplace(addI, std::map<GlobalValue*, std::map<Instruction*, std::set<GlobalValue*>>>());
                                    }
                                }
                            }
                        }
                    }

                    std::cout << "\t getAllStoreReg for a9[disp]" << std::endl; // store i32 %5, i32* @a2, align 4    --> a2 = a9[2088]
                    for (auto &a9f : a9) { // first dim a9[2088][]
                        for (auto *U : a9f.first->users()) { // %4 = inttoptr i32 %3 to i32*
//                             std::cout << "\t\t>" << std::flush; U->dump();

                            for (auto *UU : U->users()) {
//                                 std::cout << "\t\t\t>" << std::flush; UU->dump(); // %5 = load i32, i32* %4, align 4

                                for (auto *UUU : UU->users()) {
                                    if (StoreInst* s = dyn_cast<StoreInst>(UUU)) { //store i32 %5, i32* @a2, align 4    --> a2 = a9[2088]
                                        if (GlobalValue* gv = dyn_cast<GlobalValue>(s->getPointerOperand())) {
//                                             std::cout << "\t\t\t\t>" << std::flush; s->getPointerOperand()->dump(); //@a2
                                            a9f.second.emplace(gv, std::map<Instruction*, std::set<GlobalValue*>>());
                                        }
                                    }
                                }
                            }
                        }

                    }

                    // Find second dimension
                    std::cout << "\t getAllStoreReg for a9[disp][disp2]" << std::endl; //store i32 %9, i32* @a15, align 4   --> a15 = a2[2594]
                    for (auto &a9f : a9) {
//                         std::cout << "\t>" << std::flush; a9f.first->dump();

                        for (auto &a9fr : a9f.second) {
//                             std::cout << "\t\t>" << std::flush; a9fr.first->dump();

                            for (auto *U : a9fr.first->users()) {
                                if (LoadInst* loadI = dyn_cast<LoadInst>(U)) { // %8 = load i32, i32* @a2, align 4
//                                     std::cout << "\t\t\t>" << std::flush; loadI->dump();

                                    for (auto *UU : loadI->users()) {
                                        if (Instruction* addI = dyn_cast<Instruction>(UU)) {
                                            if (addI->getOpcode() == Instruction::Add) { // %9 = add i32 %8, 2594
                                                auto it = a9fr.second.emplace(addI, std::set<GlobalValue*>());
//                                                 std::cout << "\t\t\t\t>" << std::flush; addI->dump();

                                                for (auto *UUU : addI->users()) { //store i32 %9, i32* @a15, align 4   --> a15 = a2[2594]
//                                                     std::cout << "\t\t\t\t\t>" << std::flush; UUU->dump();
                                                    if (StoreInst* storeI = dyn_cast<StoreInst>(UUU)) {
                                                        if (GlobalVariable* gv = dyn_cast<GlobalVariable>(storeI->getPointerOperand())) {
                                                            it.first->second.insert(gv); //store a15
                                                        }
                                                    }
                                                }

                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    //Build a9Reverse for later search
                    std::map<GlobalValue*, std::map<Instruction*, std::map<GlobalValue*, std::set<Instruction*>>>> a9Reverse; // a15[2594] = a9[2088][]
                    for (auto &i : a9)
                    for (auto &j : i.second)
                    for (auto &k : j.second)
                    for (auto &l : k.second) {
//                         i.first->dump();
//                         j.first->dump();
//                         k.first->dump();
//                         l->dump();

                        a9Reverse[l][k.first][j.first].insert(i.first);
                    }

                    for (auto &i : a9)
                    for (auto &j : i.second)
                    for (auto &k : j.second)
                    for (auto &l : k.second) {
//                         i.first->dump();
//                         j.first->dump();
//                         k.first->dump();
//                         l->dump();

                        for (auto *U : l->users()) {
                            if (LoadInst* li = dyn_cast<LoadInst>(U)) { //%10 = load i32, i32* @a15, align 4
//                                 std::cout << "\t>" << std::flush; li->dump();
//                                 std::cout << "\t\t>" << std::flush; li->getPointerOperand()->dump();

                                auto it = li->getParent()->begin();
                                auto end = li->getParent()->end();
                                for (; it != end; ++it) {
//                                     it->dump();
                                    if (LoadInst *lIns = dyn_cast<LoadInst>(it)) { //find pos of %10 = load i32, i32* @a15, align 4
                                        if (lIns == li) {
                                            break;
                                        }
                                    }
                                }

                                if (it != end) {
                                    while (--it != li->getParent()->begin()) { //check all storeInst before %10 = load i32, i32* @a15, align 4
                                        if (StoreInst *s = dyn_cast<StoreInst>(it)) {
                                            if (s->getPointerOperand() == l) { // if same register
                                                if (Instruction* inst = dyn_cast<Instruction>(s->getValueOperand())) { //check if known add disp via a9[][], e.g. %9 = add i32 %8, 2594
                                                    if (inst->getOpcode() == Instruction::Add) {

                                                        auto fAddDispSecondDim = a9Reverse[l].find(inst);
                                                        if (fAddDispSecondDim == std::end(a9Reverse[l])) {
//                                                             std::cout << "Found falsePositiv Store " << std::flush; s->dump();
//                                                             std::cout << "\talloc was " << std::flush; inst->dump();
                                                            break;
                                                        }

//                                                         std::cout << "Found matching a9[X][Y] store, search usage of store " << std::flush; s->dump();
//                                                         std::cout << "\tY:" << std::flush; inst->dump();

                                                        //find store i32 %13, i32* @d15, align 4  --> d15 = *a15
                                                        for (auto *UU : li->users()) { //%11 = inttoptr i32 %10 to i16*
//                                                             UU->dump(); //%11 = inttoptr i32 %10 to i16*

                                                            for (auto *UUU : UU->users()) {
//                                                                 UUU->dump(); //%12 = load i16, i16* %11, align 2

                                                                if (LoadInst* li = dyn_cast<LoadInst>(UUU)) {
                                                                    ConstantInt* X = cast<ConstantInt>((*(fAddDispSecondDim->second.begin())->second.begin())->getOperand(1));
                                                                    ConstantInt* Y = cast<ConstantInt>(inst->getOperand(1));

                                                                    std::cout << "X: " << std::dec << X->getSExtValue() << std::endl;
                                                                    std::cout << "Y: " << std::dec << Y->getSExtValue() << std::endl;
                                                                    long unsigned int valOnPos = getValOnPos(getValOnPos(0x8016D340, X->getSExtValue(), 4), Y->getSExtValue(), li->getType()->getIntegerBitWidth() / 8);
                                                                    std::cout << "Replace load with ConstInt: 0x" << std::hex << valOnPos << std::endl;

                                                                    li->replaceAllUsesWith(ConstantInt::get(li->getType(), valOnPos));


//                                                                     for (auto *UUUU : UUU->users()) {
// //                                                                     UUUU->dump(); //%13 = sext i16 %12 to i32
//
//                                                                         for (auto *UUUUU : UUUU->users()) {
//                                                                             if (StoreInst* finalStore = dyn_cast<StoreInst>(UUUUU)) {
//                                                                                 std::cout << "OldStoreInst: " << std::flush; finalStore->dump(); //store i32 %13, i32* @d15, align 4  --> d15 = *a15
//                                                                                 std::cout << "VAL: " << std::flush; finalStore->getValueOperand()->dump();
//                                                                                 std::cout << "PTR: " << std::flush; finalStore->getPointerOperand()->dump();
//
//                                                                                 ConstantInt* X = cast<ConstantInt>((*(fAddDispSecondDim->second.begin())->second.begin())->getOperand(1));
//                                                                                 ConstantInt* Y = cast<ConstantInt>(inst->getOperand(1));
//
//                                                                                 std::cout << "X: " << std::dec << X->getSExtValue() << std::endl;
//                                                                                 std::cout << "Y: " << std::dec << Y->getSExtValue() << std::endl;
//
//                                                                                 long unsigned int valOnPos = getValOnPos(getValOnPos(0x8016D340, X->getSExtValue(), 4), Y->getSExtValue(), li->getType()->getIntegerBitWidth() / 8);
//                                                                                 std::cout << "Replace store with ConstInt: 0x" << std::hex << valOnPos << std::endl;
//                                                                                 finalStore->getValueOperand()->replaceAllUsesWith(ConstantInt::get(finalStore->getValueOperand()->getType(), valOnPos));
// //                                                                                 finalStore->getValueOperand()->replaceAllUsesWith(ConstantInt::get(finalStore->getValueOperand()->getType(), 0xF2D299));
//
//                                                                                 std::cout << "NewStoreInst: " << std::flush; finalStore->dump(); //store i32 %13, i32* @d15, align 4  --> d15 = *a15
//                                                                                 break;
//                                                                             }
//                                                                         }
//                                                                     }


                                                                }



                                                            }
                                                        }
                                                        break; //found first matching add disp instruction, we can stop searching
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
//                         std::cout << "=================" << std::endl;
                    }
                }
            }
//             else if (StoreInst* s = dyn_cast<StoreInst>(&I)) {
//                 std::cout << "Store: " << std::flush; s->dump();
//
//                 std::cout << "\tPointer:" << std::flush; s->getPointerOperand()->dump();
//                 std::cout << "\tValue:" << std::flush; s->getValueOperand()->dump();
//
//
//
//
//
//
// //                 if (auto *sExtIns = dyn_cast<SExtInst>(s->getValueOperand())) {
// //                     sExtIns->has
// //                 }
//
//
//
// //                 auto str = s->getPointerOperand()->getName().str();
// //                 if (!(str.rfind("a0.", 0) == 0 ||
// //                     str.rfind("a1.", 0) == 0 ||
// //                     str.rfind("a2.", 0) == 0 ||
// //                     str.rfind("a3.", 0) == 0 ||
// //                     str.rfind("a8.", 0) == 0 ||
// //                     str.rfind("a9.", 0) == 0)) {
// //                     continue;
// //                 }
//
//                 /**
//                 * %v3_8012c21a = load i32, i32* inttoptr (i32 <OFFSET 2088> to i32*), align 8
//                 * store i32 %v3_8012c21a, i32* %<a2>.global-to-local, align 4
//                 *
//                 * %v1_8012c222 = add i32 %v3_8012c21a, <OFFSET 2594>
//                 * store i32 %v1_8012c222, i32* %a15.global-to-local, align 4
//                 * %v1_8012c226 = inttoptr i32 %v1_8012c222 to i16*
//                 * %v2_8012c226 = load i16, i16* %v1_8012c226, align 2
//                 * %v3_8012c226 = sext i16 %v2_8012c226 to i32
//                 * store i32 %v3_8012c226, i32* %d15.global-to-local, align 4
//                 *
//                 */
//                 if (Instruction* ins = dyn_cast<Instruction>(s->getValueOperand())) {
//                     for (auto *U : ins->users()) {
//                         llvm::ConstantInt* disp = nullptr;
//                         llvm::ConstantInt* baseAddress = nullptr;
//                         if (Instruction* fAddDispIns = dyn_cast<Instruction>(U)) {
//                             if (fAddDispIns->getOpcode() == Instruction::Add) {
//                                 if (fAddDispIns->getNumOperands() >= 2 && fAddDispIns->getOperand(1)->getType()->isIntegerTy()) {
//                                     disp = dyn_cast<ConstantInt>(fAddDispIns->getOperand(1)); //found disp
//
//                                     if (Instruction *intToPtrIns = dyn_cast<Instruction>(fAddDispIns->getOperand(0))) {
//                                         if (auto* c = dyn_cast<Constant>(intToPtrIns->getOperand(0))) {
//                                             baseAddress = dyn_cast<ConstantInt>(c->getOperand(0)); //found baseAddress
//                                         }
//                                     }
//                                 }
//                             }
//                         }
//                         if (!disp || !baseAddress) {
//                             continue;
//                         }
//
//                         auto dispValue = disp->getSExtValue();
//                         auto baseAddressValue = baseAddress->getZExtValue();
//                         for (auto *UU : U->users()) {
//                             for (auto *UUU : UU->users()) {
//                                 if (LoadInst* li = dyn_cast<LoadInst>(UUU)) {
//
//                                     std::cout << "\tReplace " << s->getPointerOperand()->getName().str() <<
//                                         "[0x" << std::hex << baseAddressValue << "][" << std::dec << dispValue << "] "
//                                         "LOAD with const " << std::dec << dispValue << std::endl;
//                                     if (li->getType() == disp->getType()) {
//                                         li->replaceAllUsesWith(disp);
//                                     } else {
//                                         li->replaceAllUsesWith(llvm::ConstantInt::get(li->getType(), dispValue));
//                                     }
//                                 }
//                             }
//                         }
//                     }
//                 }
//
//             }
// //             else if (LoadInst* li = dyn_cast<LoadInst>(&I)) {
// //                 if (auto* c = dyn_cast<Constant>(li->getOperand(0))) {
// //                     auto* baseAddress = dyn_cast<ConstantInt>(c->getOperand(0)); //found baseAddress
// //                     std::cout << "\tReplace " << li->getPointerOperand()->getName().str() <<
// //                         "[0x" << std::hex << baseAddress->getZExtValue() << "] LOAD with const " << std::dec << 999 << std::endl;
// //
// //                     li->replaceAllUsesWith(llvm::ConstantInt::get(li->getType(), 999));
// //                 }
// //             }
	}

	return foundA9;
}

long unsigned int TricoreLoad::getValOnPos(long base, long disp, unsigned int size) {
    if (!Input.good()) {
        llvm::errs() << "Bad Input file: " << '\n';
        exit(1);
    }

    long unsigned int mask = 0; //~(~0 << (size * 8));
    switch (size) {
        case 8: mask = 0xFFFFFFFFFFFFFFFF; break;
        case 4: mask = 0xFFFFFFFF; break;
        case 2: mask = 0xFFFF; break;
        case 1: mask = 0xFF; break;
        default: assert(false && "Unknown Mask");
    }

    char buffer[size];

    Input.seekg(base - 0x80000000, Input.beg);
    Input.seekg(disp, Input.cur);
    Input.read(buffer, size);

    long unsigned int ret = 0;
    for (int i = size; i >= 0; --i) {
        ret |= ((buffer[i] & 0xFF) << (i * 8));
    }
    ret &= mask;

    return ret;
}


} // namespace bin2llvmir
} // namespace retdec
