#ifndef RETDEC_CAPSTONE2LLVMIR_TRICORE_DEFS_H
#define RETDEC_CAPSTONE2LLVMIR_TRICORE_DEFS_H

#include "capstone/capstone.h"
#include <bitset>

/**
 * @src TriCore 1.6 User manuel 1
 *
 */
typedef enum tricore_reg {
    TRICORE_REG_INVALID = 0,

    //Flags in PSW
    TRICORE_REG_CF, //Carry
    TRICORE_REG_OF, //Overflow
    TRICORE_REG_SOF, //Sticky overflow
    TRICORE_REG_AOF, //Advance Overflow
    TRICORE_REG_SAOF, //Sticky Advance Overflow

        TRICORE_REG_ZERO, //Zero Reg
    TRICORE_REG_PC = 0xfe08, // PC [31:1] rw Program Counter, RES 0 - Reserved
    TRICORE_REG_PSW = 0xfe04, //Program Status Word Register
    TRICORE_REG_PCXI = 0xfe00, //Previous Context Information and Pointer Register
    TRICORE_REG_ISP = 0xfe28, //Interrupt Stack Pointer
    TRICORE_REG_SYSCON = 0xfe14, //System Control Register
    TRICORE_REG_CPU_ID = 0xfe18, //CPU Identification Register
    TRICORE_REG_COMPAT = 0x9f00, //Compatibility Mode Register

    //> General purpose registers
    //16 Data registers (DGPRs), D[0] to D[15]. 32 bit
    // 0xFF00 + n*4
    TRICORE_REG_D_0 = 0xff00,
    TRICORE_REG_D_1 = TRICORE_REG_D_0 + 4,
    TRICORE_REG_D_2 = TRICORE_REG_D_1 + 4,
    TRICORE_REG_D_3 = TRICORE_REG_D_2 + 4,
    TRICORE_REG_D_4 = TRICORE_REG_D_3 + 4,
    TRICORE_REG_D_5 = TRICORE_REG_D_4 + 4,
    TRICORE_REG_D_6 = TRICORE_REG_D_5 + 4,
    TRICORE_REG_D_7 = TRICORE_REG_D_6 + 4,
    TRICORE_REG_D_8 = TRICORE_REG_D_7 + 4,
    TRICORE_REG_D_9 = TRICORE_REG_D_8 + 4,
    TRICORE_REG_D_10 = TRICORE_REG_D_9 + 4,
    TRICORE_REG_D_11 = TRICORE_REG_D_10 + 4,
    TRICORE_REG_D_12 = TRICORE_REG_D_11 + 4,
    TRICORE_REG_D_13 = TRICORE_REG_D_12 + 4,
    TRICORE_REG_D_14 = TRICORE_REG_D_13 + 4,
    TRICORE_REG_D_15 = TRICORE_REG_D_14 + 4,

    //16 Address registers (AGPRs), A[0] to A[15]. 32 bit
    // 0xFF80 + n*4
    TRICORE_REG_A_0 = 0xff80,
    TRICORE_REG_A_1 = TRICORE_REG_A_0 + 4,
    TRICORE_REG_A_2 = TRICORE_REG_A_1 + 4,
    TRICORE_REG_A_3 = TRICORE_REG_A_2 + 4,
    TRICORE_REG_A_4 = TRICORE_REG_A_3 + 4,
    TRICORE_REG_A_5 = TRICORE_REG_A_4 + 4,
    TRICORE_REG_A_6 = TRICORE_REG_A_5 + 4,
    TRICORE_REG_A_7 = TRICORE_REG_A_6 + 4,
    TRICORE_REG_A_8 = TRICORE_REG_A_7 + 4,
    TRICORE_REG_A_9 = TRICORE_REG_A_8 + 4,
    TRICORE_REG_A_10 = TRICORE_REG_A_9 + 4,
    TRICORE_REG_A_11 = TRICORE_REG_A_10 + 4,
    TRICORE_REG_A_12 = TRICORE_REG_A_11 + 4,
    TRICORE_REG_A_13 = TRICORE_REG_A_12 + 4,
    TRICORE_REG_A_14 = TRICORE_REG_A_13 + 4,
    TRICORE_REG_A_15 = TRICORE_REG_A_14 + 4,

    //8 Extended data registers E[0] := D[0]:D[1], E[2] := D[2]:D[3]
    TRICORE_REG_E_0 = TRICORE_REG_D_0,
    TRICORE_REG_E_2 = TRICORE_REG_E_0 + 8,
    TRICORE_REG_E_4 = TRICORE_REG_E_2 + 8,
    TRICORE_REG_E_6 = TRICORE_REG_E_4 + 8,
    TRICORE_REG_E_8 = TRICORE_REG_E_6 + 8,
    TRICORE_REG_E_10 = TRICORE_REG_E_8 + 8,
    TRICORE_REG_E_12 = TRICORE_REG_E_10 + 8,
    TRICORE_REG_E_14 = TRICORE_REG_E_12 + 8,

    //8 Extended address registers P[0] := A[0]:A[1], P[2] := A[2]:A[3]
    TRICORE_REG_P_0 = TRICORE_REG_A_0,
    TRICORE_REG_P_2 = TRICORE_REG_P_0 + 8,
    TRICORE_REG_P_4 = TRICORE_REG_P_2 + 8,
    TRICORE_REG_P_6 = TRICORE_REG_P_4 + 8,
    TRICORE_REG_P_8 = TRICORE_REG_P_6 + 8,
    TRICORE_REG_P_10 = TRICORE_REG_P_8 + 8,
    TRICORE_REG_P_12 = TRICORE_REG_P_10 + 8,
    TRICORE_REG_P_14 = TRICORE_REG_P_12 + 8,

    // alias registers
    TRICORE_REG_SP = TRICORE_REG_A_10, //Stack Pointer
    TRICORE_REG_RA = TRICORE_REG_A_11, //Return Address

    //Access Control Registers
    TRICORE_REG_BMACON = 0x9004, //BIST Mode Access Control
    TRICORE_REG_SMACON = 0x900c, //SIST Mode Access Control Register

    //Context Management Registers
    TRICORE_REG_FCX = 0xfe38, //Free CSA List Head Pointer
    TRICORE_REG_PCX = 0xfe00, //Previous Context Pointer Register
    TRICORE_REG_LCX = 0xfe3c, //Free CSA List Limit Pointer Register

    //Interrupt System
    ////Service Request Control Register (SRC)

    //Interrupt Control Registers
    TRICORE_REG_ICR = 0xfe2c, //ICU Interrupt Control Register
    TRICORE_REG_BIV = 0xfe20, //Base Interrupt Vector Table Pointer

    //Trap Control Registers
    TRICORE_REG_BTV = 0xfe24, //Base Trap Vector Table Pointer
    TRICORE_REG_PSTR = 0x9200, //Program Synchronous Error Trap Register
    TRICORE_REG_DSTR = 0x9010, //Data Synchronous Error Trap Register
    TRICORE_REG_DATR = 0x9018, //Data Asynchronous Error Trap Register
    TRICORE_REG_DEADD = 0x901c, //Data Error Address Register

    //Memory Integrity Error Mitigation Registers
    TRICORE_REG_CCPIER = 0x9218, //Count of Corrected Program Memory Integrity Errors Register
    TRICORE_REG_CCDIER = 0x9028, //Count of Corrected Data Integrity Errors Register
    TRICORE_REG_PIETR = 0x9214, //Program Integrity Error Trap Register
    TRICORE_REG_PIEAR = 0x9210, //Program Integrity Error Address Register
    TRICORE_REG_DIETR = 0x9024, //Data Integrity Error Trap Register
    TRICORE_REG_DIEAR = 0x9020, //Data Integrity Error Address Register
    TRICORE_REG_MIECON = 0x9044, //Memory Integrity Error Control Register

    //PMA Register
    TRICORE_REG_PMA0 = 0x801c, //Physical Memory Attributes
    TRICORE_REG_PCON0 = 0x920c, //Program Memory Configuration Register 0
    TRICORE_REG_PCON1 = 0x9204, //Program Memory Configuration Register 1
    TRICORE_REG_PCON2 = 0x9208, //Program Memory Configuration Register 2

    //Data Memory Configuration Registers
    TRICORE_REG_DCON0 = 0x9040, //Data Memory Configuration Register 0
    TRICORE_REG_DCON1 = 0x9008, //Data Memory Configuration Register 1
    TRICORE_REG_DCON2 = 0x9000, //Data Memory Configuration Register 2

    //Range Based Memory Protection Registers
    //Data Protection Range Register Upper Bound
    // 0xc004 + x * 0x8
    TRICORE_REG_DPRx_0U = 0xc004,
    TRICORE_REG_DPRx_1U = TRICORE_REG_DPRx_0U + 0x8,
    TRICORE_REG_DPRx_2U = TRICORE_REG_DPRx_1U + 0x8,
    TRICORE_REG_DPRx_3U = TRICORE_REG_DPRx_2U + 0x8,
    TRICORE_REG_DPRx_4U = TRICORE_REG_DPRx_3U + 0x8,
    TRICORE_REG_DPRx_5U = TRICORE_REG_DPRx_4U + 0x8,
    TRICORE_REG_DPRx_6U = TRICORE_REG_DPRx_5U + 0x8,
    TRICORE_REG_DPRx_7U = TRICORE_REG_DPRx_6U + 0x8,
    //Data Protection Range Register Lower Bound
    // 0xc000 + x*0x8
    TRICORE_REG_DPRx_0L = 0xc000,
    TRICORE_REG_DPRx_1L = TRICORE_REG_DPRx_0L + 0x8,
    TRICORE_REG_DPRx_2L = TRICORE_REG_DPRx_1L + 0x8,
    TRICORE_REG_DPRx_3L = TRICORE_REG_DPRx_2L + 0x8,
    TRICORE_REG_DPRx_4L = TRICORE_REG_DPRx_3L + 0x8,
    TRICORE_REG_DPRx_5L = TRICORE_REG_DPRx_4L + 0x8,
    TRICORE_REG_DPRx_6L = TRICORE_REG_DPRx_5L + 0x8,
    TRICORE_REG_DPRx_7L = TRICORE_REG_DPRx_6L + 0x8,

    //Code Protection Range Registers
    //Code Protection Range Register Upper Bound
    // 0xd004 + x*0x8
    TRICORE_REGCPRx_0U = 0xd004,
    TRICORE_REGCPRx_1U = TRICORE_REGCPRx_0U + 0x8,
    TRICORE_REGCPRx_2U = TRICORE_REGCPRx_1U + 0x8,
    TRICORE_REGCPRx_3U = TRICORE_REGCPRx_2U + 0x8,
    TRICORE_REGCPRx_4U = TRICORE_REGCPRx_3U + 0x8,
    TRICORE_REGCPRx_5U = TRICORE_REGCPRx_4U + 0x8,
    TRICORE_REGCPRx_6U = TRICORE_REGCPRx_5U + 0x8,
    TRICORE_REGCPRx_7U = TRICORE_REGCPRx_6U + 0x8,
    //Code Protection Range Register Lower Bound
    // 0xd000 + x*0x8
    TRICORE_REG_CPRx_0L = 0xd000,
    TRICORE_REG_CPRx_1L = TRICORE_REG_CPRx_0L + 0x8,
    TRICORE_REG_CPRx_2L = TRICORE_REG_CPRx_1L + 0x8,
    TRICORE_REG_CPRx_3L = TRICORE_REG_CPRx_2L + 0x8,
    TRICORE_REG_CPRx_4L = TRICORE_REG_CPRx_3L + 0x8,
    TRICORE_REG_CPRx_5L = TRICORE_REG_CPRx_4L + 0x8,
    TRICORE_REG_CPRx_6L = TRICORE_REG_CPRx_5L + 0x8,
    TRICORE_REG_CPRx_7L = TRICORE_REG_CPRx_6L + 0x8,
    //Data Protection Set Configuration Registers
    // 0xe000 + s*0x80
    TRICORE_REG_DPS0 = 0xe000,
    TRICORE_REG_DPS1 = TRICORE_REG_DPS0 + 0x80,
    TRICORE_REG_DPS2 = TRICORE_REG_DPS1 + 0x80,
    TRICORE_REG_DPS3 = TRICORE_REG_DPS2 + 0x80,
    //Code Protection Set Configuration Register
    // 0xe200 + s*0x80
    TRICORE_REG_CPS0 = 0xe200,
    TRICORE_REG_CPS1 = TRICORE_REG_CPS0 + 0x80,
    TRICORE_REG_CPS2 = TRICORE_REG_CPS1 + 0x80,
    TRICORE_REG_CPS3 = TRICORE_REG_CPS2 + 0x80,

    //Temporal Protection System Registers
    // 0xe404 + x*0x4
    TRICORE_REG_TPS_TIMER0 = 0xe404,
    TRICORE_REG_TPS_TIMER1 = TRICORE_REG_TPS_TIMER0 + 0x4,
//     TRICORE_REG_TPS_CON = 0x//Temporal Protection System Control Register

    //FPU CSFR Registers
    TRICORE_REG_FPU_TRAP_CON = 0xa000, //Trap Control Register
    TRICORE_REG_FPU_TRAP_PC = 0xa004, //Trapping Instruction Program Counter
    TRICORE_REG_FPU_TRAP_OPC = 0xa008, //Trapping Instruction Opcode
    TRICORE_REG_FPU_TRAP_SRC1 = 0xa010, //Trapping Instruction Operand
    TRICORE_REG_FPU_TRAP_SRC2 = 0xa014, //Trapping Instruction Operand
    TRICORE_REG_FPU_TRAP_SRC3 = 0xa018, //Trapping Instruction Operand
    TRICORE_REG_FPU_ID = 0xa020, //FPU Module Identification

//     //Core Debug Controller (CDC)
//     TRICORE_REG_DBGSR = 0xfd00, //Debug Status Register
//     TRICORE_REG_EXEVT = 0xfd08, //External Event Register
//     TRICORE_REG_CREVT = 0xfd0c, //Core Register Access Event
//     TRICORE_REG_SWEVT = 0xfd10, //Software Debug Event
//     //Trigger Event x
//     // 0xf0xx
//     TRIORE_REG_TR0EVT = 0xf000,
//     TRIORE_REG_TR1EVT = 0xf011,
//     TRIORE_REG_TR2EVT = 0xf022,
//     TRIORE_REG_TR3EVT = 0xf033,
//     TRIORE_REG_TR4EVT = 0xf044,
//     TRIORE_REG_TR5EVT = 0xf055,
//     TRIORE_REG_TR6EVT = 0xf066,
//     TRIORE_REG_TR7EVT = 0xf077,
//     //Trigger Address x
//     // 0xf0xx
//     TRIORE_REG_TR0ADR = 0xf000,
//     TRIORE_REG_TR1ADR = 0xf011,
//     TRIORE_REG_TR2ADR = 0xf022,
//     TRIORE_REG_TR3ADR = 0xf033,
//     TRIORE_REG_TR4ADR = 0xf044,
//     TRIORE_REG_TR5ADR = 0xf055,
//     TRIORE_REG_TR6ADR = 0xf066,
    //.........

    TRICORE_REG_ENDING // <-- mark the end of the list or registers
} tricore_reg;



typedef enum TRICORE_OF { // Opcode format
    TRICORE_OF_INVALID,

    //16-bit Opcode Formats
    TRICORE_OF_SB,
    TRICORE_OF_SBC,
    TRICORE_OF_SBR,
    TRICORE_OF_SBRN,
    TRICORE_OF_SC,
    TRICORE_OF_SLR,
    TRICORE_OF_SLRO,
    TRICORE_OF_SR,
    TRICORE_OF_SRC,
    TRICORE_OF_SRO,
    TRICORE_OF_SRR,
    TRICORE_OF_SRRS,
    TRICORE_OF_SSR,
    TRICORE_OF_SSRO,

    //32-bit Opcode Formats
    TRICORE_OF_ABS,
    TRICORE_OF_ABSB,
    TRICORE_OF_B,
    TRICORE_OF_BIT,
    TRICORE_OF_BO,
    TRICORE_OF_BOL,
    TRICORE_OF_BRC,
    TRICORE_OF_BRN,
    TRICORE_OF_BRR,
    TRICORE_OF_RC,
    TRICORE_OF_RCPW,
    TRICORE_OF_RCR,
    TRICORE_OF_RCRR,
    TRICORE_OF_RCRW,
    TRICORE_OF_RLC,
    TRICORE_OF_RR,
    TRICORE_OF_RR1,
    TRICORE_OF_RR2,
    TRICORE_OF_RRPW,
    TRICORE_OF_RRR,
    TRICORE_OF_RRR1,
    TRICORE_OF_RRR2,
    TRICORE_OF_RRRR,
    TRICORE_OF_RRRW,
    TRICORE_OF_SYS,
} TRICORE_OF;

//> Operand type for instruction's operands
typedef enum tricore_op_type {
    TRICORE_OP_INVALID = 0, // = CS_OP_INVALID (Uninitialized).
    TRICORE_OP_REG, // = CS_OP_REG (Register operand).
    TRICORE_OP_IMM, // = CS_OP_IMM (Immediate operand).
    TRICORE_OP_MEM, // = CS_OP_MEM (Memory operand).
} tricore_op_type;

// Instruction's operand referring to memory
// This is associated with MIPS_OP_MEM operand type above
typedef struct tricore_op_mem {
    tricore_reg base;    // base register
    uint64_t disp;     // displacement/offset value

    tricore_op_mem(tricore_reg base, int64_t disp) :
            base(base),
            disp(disp) {};
} tricore_op_mem;

// Instruction operand
typedef struct cs_tricore_op {
    tricore_op_type type;    // operand type
    union {
        tricore_reg reg;    // register value for REG operand
        uint64_t imm;        // immediate value for IMM operand
        tricore_op_mem mem;    // base/index/scale/disp value for MEM operand
    };

    cs_tricore_op() :
        type(TRICORE_OP_INVALID),
        imm(0) {};

    cs_tricore_op(tricore_reg reg) :
        type(TRICORE_OP_REG),
        reg(reg) {};

    cs_tricore_op(uint64_t imm) :
        type(TRICORE_OP_IMM),
        imm(imm) {};

    cs_tricore_op(tricore_reg base, uint64_t disp) :
        type(TRICORE_OP_MEM),
        mem(tricore_op_mem(base, disp)) {};

} cs_tricore_op;

// Instruction structure
typedef struct cs_tricore {
    TRICORE_OF format;

    // Number of operands of this instruction,
    // or 0 when instruction has no operand.
    uint8_t op_count;
    cs_tricore_op operands[8]; // operands for this instruction.

    cs_tricore(cs_insn* i);
} cs_tricore;

typedef enum tricore_insn {
    TRICORE_INS_INVALID = 0,

    // _c := constant
    // _r := register
    // _z := zero extend

    TRICORE_INS_J_24 = 0x1D, //DONE
    TRICORE_INS_J_8 = 0x3C, //DONE
    TRICORE_INS_JA = 0x9D, //DONE
    TRICORE_INS_JEQ_15_c = 0xDF, //DONE
    TRICORE_INS_JEQ_15_r = 0x5F,
    TRICORE_INS_JEQ_4_c = 0x1E,
    TRICORE_INS_JEQ_4_c_PLUS_16 = 0x9E,
    TRICORE_INS_JEQ_4_r = 0x3E,
    TRICORE_INS_JEQ_4_r_PLUS_16 = 0xBE,
    TRICORE_INS_JEQ_A = 0x7D,
    TRICORE_INS_JGE_U_c = 0xFF,
    TRICORE_INS_JGE_U_r = 0x7F,
    TRICORE_INS_JGE_UD_c = 0xFF,
    TRICORE_INS_JGE_UD_r = 0x7F,
    TRICORE_INS_JGEZ = 0xCE,
    TRICORE_INS_JGTZ = 0x4E,
    TRICORE_INS_JI_32 = 0x2D,
    TRICORE_INS_JI_16 = 0xDC,
    TRICORE_INS_JL = 0x5D,
    TRICORE_INS_JLA = 0xDD,
    TRICORE_INS_JLEZ = 0x8E,
    TRICORE_INS_JLI = 0x2D,
    TRICORE_INS_JLT_U_c = 0xBF,
    TRICORE_INS_JLT_U_r = 0x3F,
    TRICORE_INS_JLT_U_c_z = 0xBF,
    TRICORE_INS_JLT_U_r_z = 0x3F,
    TRICORE_INS_JLTZ = 0x0E,
    TRICORE_INS_JNE_c = TRICORE_INS_JEQ_15_c, //DONE
    TRICORE_INS_JNE_r = 0x5F,
    TRICORE_INS_JNE_16 = 0x5E,
    TRICORE_INS_JNE_16_z = 0xDE,
    TRICORE_INS_JNE_16_z_r = 0x7E,
    TRICORE_INS_JNE_16_z_r_PLUS_16 = 0xFE,
    TRICORE_INS_JNEA = 0x7D,
    TRICORE_INS_JNED_c = 0x9F,
    TRICORE_INS_JNED_r = 0x1F,
    TRICORE_INS_JNEI_c = 0x9F,
    TRICORE_INS_JNEI_r = 0x1F,
    TRICORE_INS_JNZ_c = 0xEE,
    TRICORE_INS_JNZ_r = 0xF6,
    TRICORE_INS_JNZA = 0xBD,
    TRICORE_INS_JNZA_16 = 0x7C,
    TRICORE_INS_JNZT = 0x6F,
    TRICORE_INS_JNZT_16 = 0xAE,
    TRICORE_INS_JZ_c = 0x6E,
    TRICORE_INS_JZ_r = 0x76,
    TRICORE_INS_JZA = 0xBD,
    TRICORE_INS_JZA_16 = 0xBC,
    TRICORE_INS_JZT = 0x6F,
    TRICORE_INS_JZT_16 = 0x2E,

    TRICORE_INS_LD_A = 0x85,
    TRICORE_INS_LD_HD = 0x8C, //DONE

    TRICORE_INS_NOP = 0x00

} tricore_insn;

#endif
