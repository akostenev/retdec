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
    baseA9 = 0x8016D340;
    baseA1 = 0x8002CF9C;
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
bool TricoreLoad::runOnModule(Module& M) {
//     return false;
    if (!ConfigProvider::getConfig(&M, config))
    {
            LOG << "[ABORT] config file is not available\n";
            return false;
    }

    auto a9On2088 = getValOnPos(0x8016D340, 2088, 4);
    std::cout << "Word on a9[2088]: " << std::hex << a9On2088 << std::endl;
    std::cout << "HWORD on a9[2088][2594]: " << std::hex << getValOnPos(a9On2088, 2594, 2) << std::endl;

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

    bool foundA1 = false;
    bool foundA9 = false;

    for (auto &F : M.getFunctionList())
    for (BasicBlock &B : F)
    for (Instruction &I : B) {
        if (LoadInst* l = dyn_cast<LoadInst>(&I)) {
            if (!foundA9 && l->getPointerOperand() == config->getLlvmRegister("a9")) { // %2 = load i32, i32* @a9, align 4
                foundA9 = true;
                std::map<Instruction*, std::map<GlobalValue*, std::map<Instruction*, std::set<GlobalValue*>>>> a9; // a9[2088] -> a2, a2[2594]

                for (auto *U : l->getPointerOperand()->users()) {
                    if (LoadInst* a9Load = dyn_cast<LoadInst>(U)) {
                        for (auto *U : a9Load->users()) {
                            if (Instruction* addI = dyn_cast<Instruction>(U))
                            if (addI->getOpcode() == Instruction::Add) { //// %3 = add i32 %2, 2088
                                    a9.emplace(addI, std::map<GlobalValue*, std::map<Instruction*, std::set<GlobalValue*>>>());
                            }
                        }
                    }
                }

                for (auto &a9f : a9) // first dim a9[2088][] --> store i32 %5, i32* @a2, align 4    --> a2 = a9[2088]
                for (auto *U : a9f.first->users()) // %4 = inttoptr i32 %3 to i32*
                for (auto *UU : U->users())
                for (auto *UUU : UU->users()) {
                    if (StoreInst* s = dyn_cast<StoreInst>(UUU)) { //store i32 %5, i32* @a2, align 4    --> a2 = a9[2088]
                    if (GlobalValue* gv = dyn_cast<GlobalValue>(s->getPointerOperand()))
                        a9f.second.emplace(gv, std::map<Instruction*, std::set<GlobalValue*>>());
                    }
                }

                // Find second dimension  --> store i32 %9, i32* @a15, align 4   --> a15 = a2[2594]
                for (auto &a9f : a9)
                for (auto &a9fr : a9f.second)
                for (auto *U : a9fr.first->users()) {
                    if (LoadInst* loadI = dyn_cast<LoadInst>(U)) { // %8 = load i32, i32* @a2, align 4
                        for (auto *UU : loadI->users()) {
                            if (Instruction* addI = dyn_cast<Instruction>(UU))
                            if (addI->getOpcode() == Instruction::Add) { // %9 = add i32 %8, 2594

                                auto it = a9fr.second.emplace(addI, std::set<GlobalValue*>());
                                for (auto *UUU : addI->users()) { //store i32 %9, i32* @a15, align 4   --> a15 = a2[2594]
                                    if (StoreInst* storeI = dyn_cast<StoreInst>(UUU))
                                    if (GlobalVariable* gv = dyn_cast<GlobalVariable>(storeI->getPointerOperand())) {
                                        it.first->second.insert(gv); //store a15
                                    }
                                }
                            }
                        }
                    }
                }

                //Build a9Reverse for later search
                std::map<GlobalValue*, std::map<Instruction*, std::map<GlobalValue*, std::set<Instruction*>>>> reversedA9; // a15[2594] = a9[2088][]
                for (const auto &i : a9)
                for (const auto &j : i.second)
                for (const auto &k : j.second)
                for (const auto &l : k.second) {
                    reversedA9[l][k.first][j.first].insert(i.first);
                }

                for (const auto &i : a9)
                for (const auto &j : i.second)
                for (const auto &k : j.second)
                for (const auto &l : k.second)
                for (auto *U : l->users()) {
                    if (LoadInst* li = dyn_cast<LoadInst>(U)) { //%10 = load i32, i32* @a15, align 4

                        auto it = li->getParent()->begin();
                        auto end = li->getParent()->end();
                        for (; it != end; ++it) {
                            if (LoadInst *lIns = dyn_cast<LoadInst>(it)) //find pos of %10 = load i32, i32* @a15, align 4
                            if (lIns == li) {
                                    break;
                            }
                        }

                        if (it != end) {
                            while (--it != li->getParent()->begin()) { //check all storeInst before %10 = load i32, i32* @a15, align 4
                                if (StoreInst *s = dyn_cast<StoreInst>(it))
                                if (s->getPointerOperand() == l) // if same register
                                if (Instruction* inst = dyn_cast<Instruction>(s->getValueOperand())) //check if known add disp via a9[][], e.g. %9 = add i32 %8, 2594
                                if (inst->getOpcode() == Instruction::Add) {

                                    auto fAddDispSecondDim = reversedA9[l].find(inst);
                                    if (fAddDispSecondDim == std::end(reversedA9[l])) {
                                        break; // false positive
                                    }

                                    uint64_t X, Y;
                                    if (ConstantInt *CX = dyn_cast<ConstantInt>((*(fAddDispSecondDim->second.begin())->second.begin())->getOperand(1))) {
                                        X = CX->getZExtValue();
                                    } else {
//                                         (*(fAddDispSecondDim->second.begin())->second.begin())->getOperand(1)->dump();
                                        break; // false positive
                                    }

                                    if (ConstantInt *CY = dyn_cast<ConstantInt>(inst->getOperand(1))) {
                                        Y = CY->getZExtValue();
                                    } else {
//                                         inst->getOperand(1)->dump();
                                        break; // false positive
                                    }
                                    auto ptrX = getValOnPos(baseA9, X, 4);

                                    //find store i32 %13, i32* @d15, align 4  --> d15 = *a15
                                    for (auto *UU : li->users()) //%11 = inttoptr i32 %10 to i16*
                                    for (auto *UUU : UU->users()) { //%12 = load i16, i16* %11, align 2
                                        if (LoadInst* LI = dyn_cast<LoadInst>(UUU)) {
                                            long unsigned int a9XYval = getValOnPos(ptrX, Y, LI->getType()->getIntegerBitWidth() / 8);

                                            std::cout << "Replace load a9[" << std::dec << X << "][" << std::dec << Y << "] with ConstInt: 0x" << std::hex << a9XYval << std::endl;
                                            LI->replaceAllUsesWith(ConstantInt::get(LI->getType(), a9XYval));

//                                             for (auto *UUUU : LI->users()) {
//                                                 if (SExtInst *SE = dyn_cast<SExtInst>(UUUU)) {
// //                                                     SE->replaceAllUsesWith(ConstantInt::get(SE->getType(), a9XYval));
//
//                                                     for (auto *UUUUU : SE->users()) {
//                                                         if (StoreInst *SI = dyn_cast<StoreInst>(UUUUU)) {
//                                                             SI->setOperand(0, ConstantInt::get(SE->getType(), a9XYval));
//                                                             SI->setVolatile(true);
//                                                             break;
//                                                         }
//                                                     }
//
//                                                 } else if (ZExtInst *ZE = dyn_cast<ZExtInst>(UUUU)) {
// //                                                     ZE->replaceAllUsesWith(ConstantInt::get(ZE->getType(), a9XYval));
//
//                                                      for (auto *UUUUU : ZE->users()) {
//                                                         if (StoreInst *SI = dyn_cast<StoreInst>(UUUUU)) {
//                                                             SI->setOperand(0, ConstantInt::get(ZE->getType(), a9XYval));
//                                                             SI->setVolatile(true);
//                                                             break;
//                                                         }
//                                                     }
//                                                 }
//                                             }
                                        }
                                    }
                                    break; //found first matching add disp instruction, we can stop searching
                                }
                            }
                        }
                    }
                }

            } else if (!foundA1 && l->getPointerOperand() == config->getLlvmRegister("a1")) { // %98 = load i32, i32* @a1, align 4
                foundA1 = true;
                std::map<Instruction*, GlobalValue*> a1; // a1[3596] -> a15

                for (auto *U : l->users()) { // %99 = add i32 %98, 3596
                    if (auto *AddI = dyn_cast<Instruction>(U))
                    if (AddI->getOpcode() == Instruction::Add) {
                        for (auto *UU : U->users()) { // store i32 %99, i32* @a15, align 4
                            if (auto *SI = dyn_cast<StoreInst>(UU))
                            if (auto *GV = dyn_cast<GlobalValue>(SI->getPointerOperand())) {
                                    a1.emplace(AddI, GV);
                            }
                        }
                    }
                }

                //Reverse a1 for later search
                std::map<GlobalValue*, std::set<Instruction*>> reverseA1;
                for (const auto &a : a1) {
                    reverseA1[a.second].emplace(a.first);
                }

                for (const auto &i : a1)
                for (auto *U : i.second->users()) {
                    if (LoadInst *li = dyn_cast<LoadInst>(U)) {

                        auto it = li->getParent()->begin();
                        auto end = li->getParent()->end();
                        for (; it != end; ++it) {
                            if (LoadInst *lIns = dyn_cast<LoadInst>(it)) { //find pos of %10 = load i32, i32* @a15, align 4
                                if (lIns == li) {
                                    break;
                                }
                            }
                        }

                        if (it != end) {
                            while (--it != li->getParent()->begin()) { //check all storeInst before %10 = load i32, i32* @a15, align 4
                                if (StoreInst *SI = dyn_cast<StoreInst>(it))
                                if (SI->getPointerOperand() == i.second) // if same register
                                if (Instruction* AddI = dyn_cast<Instruction>(SI->getValueOperand())) //check if known add disp via a1[], e.g. %99 = add i32 %98, 3596
                                if (AddI->getOpcode() == Instruction::Add) {

                                    auto fAddDisp = reverseA1[i.second].find(AddI);
                                    if (fAddDisp == std::end(reverseA1[i.second])) {
                                        break; // false positive
                                    }

                                    //find store i32 %13, i32* @d15, align 4  --> d15 = *a15
                                    for (auto *UU : li->users())  //  %115 = inttoptr i32 %114 to i32*
                                    for (auto *UUU : UU->users()) {
                                        if (LoadInst* LI = dyn_cast<LoadInst>(UUU)) { // %116 = load i32, i32* %115, align 4
                                            auto X = cast<ConstantInt>(i.first->getOperand(1))->getSExtValue();
                                            long unsigned int a1Xval = getValOnPos(baseA1, X, LI->getType()->getIntegerBitWidth() / 8);

                                            std::cout << "Replace load a1[" << std::dec << X << "] with ConstInt: 0x" << std::hex << a1Xval << std::endl;
                                            LI->replaceAllUsesWith(ConstantInt::get(LI->getType(), a1Xval));

//                                             for (auto *UUUU : LI->users()) {
//                                                 if (StoreInst *SI = dyn_cast<StoreInst>(UUUU)) {
//                                                     SI->setOperand(0, ConstantInt::get(LI->getType(), a1Xval));
//                                                     SI->setVolatile(true);
//                                                 }
//                                             }
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

    dumpModuleToFile(&M);

    return foundA1 || foundA9;
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
    for (int i = size - 1; i >= 0; --i) {
        ret |= ((buffer[i] & 0xFF) << (i * 8));
    }
    ret &= mask;

    return ret;
}


} // namespace bin2llvmir
} // namespace retdec
