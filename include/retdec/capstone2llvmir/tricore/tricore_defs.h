#ifndef RETDEC_CAPSTONE2LLVMIR_TRICORE_DEFS_H
#define RETDEC_CAPSTONE2LLVMIR_TRICORE_DEFS_H

#define DWORD 64
#define WORD 32
#define HALFWORD 16
#define BYTE 8

#include "capstone/capstone.h"
#include <bitset>

/**
 * @src TriCore 1.6 User manuel 1
 *
 */
typedef enum tricore_reg {
    TRICORE_REG_INVALID = 0,
    TRICORE_REG_ZERO, //Zero Reg

    //PSW and flags in PSW
    TRICORE_REG_PSW = 0xfe04, //Program Status Word Register
    TRICORE_REG_CF, //Carry
    TRICORE_REG_OF, //Overflow
    TRICORE_REG_SOF, //Sticky overflow
    TRICORE_REG_AOF, //Advance Overflow
    TRICORE_REG_SAOF, //Sticky Advance Overflow

    //(CSFR)
    TRICORE_REG_PCXI_PCX = 0xfe00, // Previous Context Information and Pointer Register
    TRICORE_REG_PC = 0xfe08, // PC [31:1] rw Program Counter, RES 0 - Reserved
    TRICORE_REG_SYSCON = 0xfe14, //System Control Register
    TRICORE_REG_CPU_ID = 0xfe18, //CPU Identification Register
    TRICORE_REG_BIV = 0xfe20, //Base Address of Interrupt Vector Table Register.
    TRICORE_REG_BTV = 0xFE24, //Base Address of Trap Vector Table Register.
    TRICORE_REG_ISP = 0xFE28, //Interrupt Stack Pointer Register.
    TRICORE_REG_ICR = 0xFE2C, //ICU Interrupt Control Register.
    TRICORE_REG_FCX = 0xFE38, //Free Context List Head Pointer Register.
    TRICORE_REG_LCX = 0xFE3C, //Free Context List Limit Pointer Register.
    TRICORE_REG_COMPAT = 0x9400, //Compatibility Mode Register.

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

    // alias registers
    TRICORE_REG_SP = TRICORE_REG_A_10, //Stack Pointer
    TRICORE_REG_RA = TRICORE_REG_A_11, //Return Address

    //Access Control Registers
    TRICORE_REG_BMACON = 0x9004, //BIST Mode Access Control
    TRICORE_REG_SMACON = 0x900c, //SIST Mode Access Control Register

    //Trap Control Registers
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

    TRICORE_REG_ENDING = 0x100000 // <-- mark the end of the list or registers
} tricore_reg;


typedef enum tricore_reg_ext {
    //8 Extended data registers E[0] := D[0]:D[1], E[2] := D[2]:D[3]
    TRICORE_REG_E_0 = TRICORE_REG_ENDING + 1,
    TRICORE_REG_E_2,
    TRICORE_REG_E_4,
    TRICORE_REG_E_6,
    TRICORE_REG_E_8,
    TRICORE_REG_E_10,
    TRICORE_REG_E_12,
    TRICORE_REG_E_14,

    //8 Extended address registers P[0] := A[0]:A[1], P[2] := A[2]:A[3]
    TRICORE_REG_P_0,
    TRICORE_REG_P_2,
    TRICORE_REG_P_4,
    TRICORE_REG_P_6,
    TRICORE_REG_P_8,
    TRICORE_REG_P_10,
    TRICORE_REG_P_12,
    TRICORE_REG_P_14,
} tricore_reg_ext;

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

typedef enum tricore_ext {
    TRICORE_EXT_THROW = 0,
    TRICORE_EXT_ZEXT_TRUNC,
    TRICORE_EXT_SEXT_TRUNC,
} tricore_ext;

typedef struct tricore_op_imm {
    uint64_t value; //immediate value
    uint8_t sizeInBit; //sizeof val in bit
    tricore_ext ext;

    tricore_op_imm(uint64_t imm, uint8_t sizeInBit = 32, tricore_ext ext = TRICORE_EXT_THROW) :
            value(imm),
            sizeInBit(sizeInBit),
            ext(ext)
            {};
} tricore_op_imm;

// Instruction's operand referring to memory
// This is associated with MIPS_OP_MEM operand type above
typedef struct tricore_op_mem {
    tricore_reg base;    // base register
    tricore_op_imm disp; // displacement/offset value
    uint8_t size; // size in bit e.g. 32:word, 16:half-word, ...
    tricore_ext ext; // Extension if size < sizeof base
    bool lea;

    tricore_op_mem(tricore_reg base, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) :
            base(base),
            disp(disp),
            size(size),
            ext(ext),
            lea(lea)
            {};
} tricore_op_mem;

// Instruction operand
typedef struct cs_tricore_op {
    tricore_op_type type;    // operand type
    bool extended; // e.g. reg E[0] = D[0]:D[1]

    union {
        tricore_reg reg;    // register value for REG operand
        tricore_op_imm imm;        // immediate value for IMM operand
        tricore_op_mem mem;    // base/index/scale/disp value for MEM operand
    };

    cs_tricore_op() :
        type(TRICORE_OP_INVALID),
        extended(false) {};

    cs_tricore_op(tricore_reg reg, bool extended = false) :
        type(TRICORE_OP_REG),
        extended(extended),
        reg(reg) {};

    cs_tricore_op(tricore_op_imm imm) :
        type(TRICORE_OP_IMM),
        extended(false),
        imm(imm) {};

    cs_tricore_op(tricore_op_mem mem) :
        type(TRICORE_OP_MEM),
        extended(false),
        mem(mem) {};

} cs_tricore_op;

// Instruction structure
typedef struct cs_tricore {
    TRICORE_OF format;

    // Number of operands of this instruction,
    // or 0 when instruction has no operand.
    uint8_t op_count;
    cs_tricore_op operands[8]; // operands for this instruction.

    uint8_t op2; //op2 for many op formats like BRN, default 0
    uint8_t n; //bits for BRN, RR, RR1, etc.

    cs_tricore(cs_insn* i);
} cs_tricore;

typedef enum tricore_insn {
    TRICORE_INS_INVALID = 0,
    TRICORE_INS_NOP = 0x00,
    TRICORE_INS_RET = 0x00,

    // _A := address
    // _c := constant
    // _r := register
    // _z := zero extend

    TRICORE_INS_ADD16 = 0x12,
    TRICORE_INS_ADDA = 0xB0,
    TRICORE_INS_ADDD_c = 0xC2,
    TRICORE_INS_ADDDD = 0x42,
    TRICORE_INS_ADDI = 0x1B,
    TRICORE_INS_ADDIH_A = 0x11,
    TRICORE_INS_ADDSCA = 0x01,
    TRICORE_INS_ADDSCA16 = 0x10,
    TRICORE_INS_CADD = 0xAB,
    TRICORE_INS_MADD = 0x13,
    TRICORE_INS_MADD_RRR2 = 0x03,

    TRICORE_INS_ANDD15 = 0x16,

    TRICORE_INS_BIT_OPERATIONS1 = 0x8F,
    TRICORE_INS_BIT_OPERATIONS2 = 0x0F,

    TRICORE_INS_CALL16 = 0x5C,
    TRICORE_INS_CALL32 = 0x6D,
    TRICORE_INS_CALLI = 0x2D,
    TRICORE_INS_CALLABS = 0xED,

    TRICORE_INS_CMOVN16 = 0xEA,

    TRICORE_INS_CMOVD = 0x2A,

    TRICORE_INS_CMP = 0x8B,

    TRICORE_INS_DIV = 0x4B,
    TRICORE_INS_DVSTEP = 0x6B,

    TRICORE_INS_EXTR = 0x37,

    TRICORE_INS_EQ16 = 0xBA,

    TRICORE_INS_FCALL = 0x61,

    TRICORE_INS_ISYNC = 0x0D,

    TRICORE_INS_INST = 0x67,

    TRICORE_INS_J32 = 0x1D,
    TRICORE_INS_JNEQ32 = 0x5F,
    TRICORE_INS_J16 = 0x3C,
    TRICORE_INS_JA = 0x9D,
    TRICORE_INS_JEQ32 = 0xDF,
    TRICORE_INS_JEQ_4_c = 0x1E,
    TRICORE_INS_JEQ_4_c_PLUS_16 = 0x9E,
    TRICORE_INS_JEQ16 = 0x3E,
    TRICORE_INS_JEQ_4_r_PLUS_16 = 0xBE,
    TRICORE_INS_JEQA = 0x7D,
    TRICORE_INS_JGE = 0xFF,
    TRICORE_INS_JGEDD = 0x7F,
    TRICORE_INS_JGEZD = 0xCE,
    TRICORE_INS_JGTZ = 0x4E,
    TRICORE_INS_JIA = 0xDC,
    TRICORE_INS_JL = 0x5D,
    TRICORE_INS_JLA = 0xDD,
    TRICORE_INS_JLTD = 0x3F,
    TRICORE_INS_JLTZ = 0x0E,
    TRICORE_INS_JLEZD = 0x8E,
    TRICORE_INS_JNED15 = 0x5E,

    TRICORE_INS_JNE_16_z = 0xDE,
    TRICORE_INS_JNE_16_z_r = 0x7E,
    TRICORE_INS_JNE_16_z_r_PLUS_16 = 0xFE,
    TRICORE_INS_JNZ_D15 = 0xEE,
    TRICORE_INS_JNZ16 = 0xF6,
    TRICORE_INS_JNZA_16 = 0x7C,
    TRICORE_INS_JNZT = 0x6F,
    TRICORE_INS_JNZT_16 = 0xAE,
    TRICORE_INS_JZ_D15 = 0x6E,
    TRICORE_INS_JZD = 0x76,
    TRICORE_INS_JZA = 0xBD,
    TRICORE_INS_JZA_16 = 0xBC,
    TRICORE_INS_JZT_16 = 0x2E,
    TRICORE_INS_JLT = 0xBF,
    TRICORE_INS_JNE_INC_DEC = 0x9F,

    TRICORE_INS_LD = 0x85,
    TRICORE_INS_LDA = 0xC8,
    TRICORE_INS_LDB = 0x05,
    TRICORE_INS_LDB_REL = 0x08,
    TRICORE_INS_LDD15 = 0x4c,
    TRICORE_INS_LD16A = 0xD4,
    TRICORE_INS_LDA_PINC = 0xC4,
    TRICORE_INS_LDD_PINC = 0x44,
    TRICORE_INS_LDHW16 = 0x94,
    TRICORE_INS_LDHW16_REL = 0x88,
    TRICORE_INS_LDW16 = 0x48,
    TRICORE_INS_LD_HD = 0x8C,
    TRICORE_INS_LD_HD_PINC = 0x84, //Load half-word, post incr //TODO find better name
    TRICORE_INS_LD_BUD = 0x39,
    TRICORE_INS_LD_BUD15 = 0x0C,
    TRICORE_INS_LDW = 0x19,
    TRICORE_INS_LD09 = 0x09,
    TRICORE_INS_LDD = 0x54,
    TRICORE_INS_LDA_OFF = 0x99,

    TRICORE_INS_0B = 0x0B,

    TRICORE_INS_LOOP = 0xFC,

    TRICORE_INS_MOVA = 0xA0,
    TRICORE_INS_MOVDD = 0x02,
    TRICORE_INS_MOVAA = 0x40,
    TRICORE_INS_MOVAD = 0x60,
    TRICORE_INS_MOVDA = 0x80,
    TRICORE_INS_MOVD = 0x82,
    TRICORE_INS_MOVD15 = 0xDA,
    TRICORE_INS_MOVD_C16 = 0x3B,
    TRICORE_INS_MOVH = 0x7B,
    TRICORE_INS_MOVH_A = 0x91,
    TRICORE_INS_MOVU = 0xBB,

    TRICORE_INS_MULD = 0x73,
    TRICORE_INS_MULD2 = 0xE2,
    TRICORE_INS_MULE = 0x53,

    TRICORE_INS_SELN = 0x2B,

    TRICORE_INS_SHAD = 0x86,
    TRICORE_INS_SHD = 0x06,

    TRICORE_INS_ST = 0xA5,
    TRICORE_INS_STA = 0xF4,
    TRICORE_INS_STB = 0x34,
    TRICORE_INS_STBA = 0x28,
    TRICORE_INS_ST_BA = 0xE9,
    TRICORE_INS_ST_BIT = 0xD5,
    TRICORE_INS_STD = 0x74,
    TRICORE_INS_STD15 = 0x78,
    TRICORE_INS_STHW = 0xA4,
    TRICORE_INS_STHW16D15 = 0xAC,
    TRICORE_INS_STHW16 = 0xB4,
    TRICORE_INS_STHW16_REL = 0xA8,
    TRICORE_INS_STW = 0x64,
    TRICORE_INS_STWA = 0x59,
    TRICORE_INS_ST89 = 0x89,
    TRICORE_INS_STB_ABS = 0x25,

    TRICORE_INS_SUBA10 = 0x20,
    TRICORE_INS_SUBD = 0xA2,
    TRICORE_INS_SUBD15 = 0x5A,
    TRICORE_INS_SUBD1516 = 0x52,

    TRICORE_INS_MFCR = 0x4D,
    TRICORE_INS_MTCR = 0xCD,

    TRICORE_INS_LEA = 0xD9,

    TRICORE_INS_ORD = 0xA6,
    TRICORE_INS_ANDD = 0x26,

} tricore_insn;

#endif
