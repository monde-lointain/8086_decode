#ifdef _MSC_VER
#include <crtdbg.h>
#endif

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <fstream>

/*******************************************************************************
 * 8086 DECODER GLOBAL VARIABLES AND DATA STRUCTURES
 *******************************************************************************/

/** Enum for indexing into the register name lookup table. */
// clang-format off
enum REGISTER
{
    AL, AH, AX,
    BL, BH, BX,
    CL, CH, CX,
    DL, DH, DX,
    SP,
    BP,
    SI,
    DI,
    NUM_REGISTERS
};

/** Lookup table for register names. */
constexpr const char *REGISTER_NAME_LUT[] = {
    "al", "ah", "ax",
    "bl", "bh", "bx",
    "cl", "ch", "cx",
    "dl", "dh", "dx",
    "sp",
    "bp",
    "si",
    "di"
};

/** Lookup table for register values. */
int16_t REGISTER_LUT[] = {
    0x0, 0x0, 0x0,
    0x0, 0x0, 0x0,
    0x0, 0x0, 0x0,
    0x0, 0x0, 0x0,
    0x0,
    0x0,
    0x0,
    0x0
};
// clang-format on

/*******************************************************************************
 * 8086 DECODER, OPCODE DECODING UTILITY FUNCTIONS
 ******************************************************************************/

/** Converts a string representation of a register to an enum one. */
static inline REGISTER register_str_to_enum(const char *reg)
{
    REGISTER result;
    if (strcmp(reg, "al") == 0)
    {
        result = AL;
    }
    else if (strcmp(reg, "ah") == 0)
    {
        result = AH;
    }
    else if (strcmp(reg, "ax") == 0)
    {
        result = AX;
    }
    else if (strcmp(reg, "bl") == 0)
    {
        result = BL;
    }
    else if (strcmp(reg, "bh") == 0)
    {
        result = BH;
    }
    else if (strcmp(reg, "bx") == 0)
    {
        result = BX;
    }
    else if (strcmp(reg, "cl") == 0)
    {
        result = CL;
    }
    else if (strcmp(reg, "ch") == 0)
    {
        result = CH;
    }
    else if (strcmp(reg, "cx") == 0)
    {
        result = CX;
    }
    else if (strcmp(reg, "dl") == 0)
    {
        result = DL;
    }
    else if (strcmp(reg, "dh") == 0)
    {
        result = DH;
    }
    else if (strcmp(reg, "dx") == 0)
    {
        result = DX;
    }
    else if (strcmp(reg, "sp") == 0)
    {
        result = SP;
    }
    else if (strcmp(reg, "bp") == 0)
    {
        result = BP;
    }
    else if (strcmp(reg, "si") == 0)
    {
        result = SI;
    }
    else if (strcmp(reg, "di") == 0)
    {
        result = DI;
    }
    else
    {
        printf("Error: Invalid register value.");
        abort();
    }
    return result;
}

/** Converts an enum representation of a register to a string one. */
static inline const char *register_enum_to_str(REGISTER reg)
{
    const char *result = {};
    switch (reg)
    {
        case AL:
            result = "al";
            break;
        case AH:
            result = "ah";
            break;
        case AX:
            result = "ax";
            break;
        case BL:
            result = "bl";
            break;
        case BH:
            result = "bh";
            break;
        case BX:
            result = "bx";
            break;
        case CL:
            result = "cl";
            break;
        case CH:
            result = "ch";
            break;
        case CX:
            result = "cx";
            break;
        case DL:
            result = "dl";
            break;
        case DH:
            result = "dh";
            break;
        case DX:
            result = "dx";
            break;
        case SP:
            result = "sp";
            break;
        case BP:
            result = "bp";
            break;
        case SI:
            result = "si";
            break;
        case DI:
            result = "di";
            break;
        default:
            printf("Error: Invalid register value.");
            abort();
    }
    return result;
}

/*******************************************************************************
 * 8086 DECODER, OPCODE DECODING SECONDARY FUNCTIONS
 ******************************************************************************/

/**
 * Finds either the offset for the memory address, or the direct address when
 * MOD = 00 and R/M = 110.
 */
static inline int16_t find_displacement(const uint8_t mod,
                                        const bool direct_address,
                                        const uint8_t *ptr,
                                        size_t &instruction_size)
{
    int16_t displacement = 0;
    if (mod == 0b01)
    {
        // 8-bit displacement
        displacement = *(const int8_t *)ptr;
        instruction_size++;
    }
    else if (mod == 0b10 || direct_address)
    {
        // 16-bit displacement
        displacement = *(const int16_t *)ptr;
        instruction_size += 2;
    }
    return displacement;
}

/** Gets data for an immediate instruction based on the W-bit. */
static inline int16_t get_data(const uint8_t w,
                               const uint8_t *ptr,
                               size_t &instruction_size)
{
    int16_t data = 0;
    // Extract data based on W
    if (w == 0)
    {
        // 8 bits of data
        data = *(const int8_t *)ptr;
        instruction_size++;
    }
    else
    {
        // 16 bits of data
        data = *(const int16_t *)ptr;
        instruction_size += 2;
    }
    return data;
}

/**
 * Prints the result for a MOV (register to memory) with an explicit size for
 * the data being stored.
 */
static inline void print_mov_reg_mem(bool direct_address,
                                     const int16_t &displacement,
                                     const char *size,
                                     const int16_t &data,
                                     const char *dest)
{
    if (direct_address)
    {
        printf("mov [%d], %s %d\n", displacement, size, data);
    }
    else if (displacement > 0)
    {
        printf("mov [%s + %d], %s %d\n", dest, displacement, size, data);
    }
    else if (displacement < 0)
    {
        // Flip sign on negative displacements so they print correctly
        printf("mov [%s - %d], %s %d\n", dest, -displacement, size, data);
    }
    else
    {
        // Leave out offset if it's zero
        printf("mov [%s], %s %d\n", dest, size, data);
    }
}

/**
 * Does the register lookup for the REG and R/M lookup tables based on the W
 * bit.
 */
static inline const char *do_register_lookup(const REGISTER choice_1,
                                             const REGISTER choice_2,
                                             const uint8_t w)
{
    const char *result;
    if (w == 0)
    {
        result = REGISTER_NAME_LUT[choice_1];
    }
    else
    {
        result = REGISTER_NAME_LUT[choice_2];
    }
    return result;
}

/**
 * Finds the register for either the REG field, or the R/M field when MOD
 * is 11.
 */
static inline const char *find_reg_rm11(const uint8_t encoding, const uint8_t w)
{
    const char *result = {};
    // Choose which registers to select from based on the field's encoding
    switch (encoding)
    {
        case 0b000:
            result = do_register_lookup(AL, AX, w);
            break;
        case 0b001:
            result = do_register_lookup(CL, CX, w);
            break;
        case 0b010:
            result = do_register_lookup(DL, DX, w);
            break;
        case 0b011:
            result = do_register_lookup(BL, BX, w);
            break;
        case 0b100:
            result = do_register_lookup(AH, SP, w);
            break;
        case 0b101:
            result = do_register_lookup(CH, BP, w);
            break;
        case 0b110:
            result = do_register_lookup(DH, SI, w);
            break;
        case 0b111:
            result = do_register_lookup(BH, DI, w);
            break;
    }
    return result;
}

/** Finds the register in the R/M field. */
static inline const char *find_rm(const uint8_t encoding)
{
    const char *result = {};
    switch (encoding)
    {
        case 0b000:
            result = "bx + si";
            break;
        case 0b001:
            result = "bx + di";
            break;
        case 0b010:
            result = "bp + si";
            break;
        case 0b011:
            result = "bp + di";
            break;
        case 0b100:
            result = "si";
            break;
        case 0b101:
            result = "di";
            break;
        case 0b110:
            result = "bp"; // Gets replaced when MOD is 00
            break;
        case 0b111:
            result = "bx";
            break;
    }
    return result;
}

/*******************************************************************************
 * 8086 DECODER, OPCODE DECODING MAIN FUNCTIONS
 ******************************************************************************/

/** Decoding function for MOV (register to register). */
static inline size_t decode_mov_reg_reg(const uint8_t *buffer,
                                        const size_t &index)
{
    // Total size of the instruction in bytes
    uint8_t instruction_size = 0;

    uint8_t first = buffer[index];
    uint8_t second = buffer[index + 1];
    instruction_size += 2;

    // Extract D bit by masking all bits but the second last, then right
    // shifting by 1
    uint8_t d = (first & 0b00000010) >> 1;

    // Extract W bit by masking all bits but the last
    uint8_t w = first & 0b00000001;

    // Extract REG field by masking all but the middle three bits, then right
    // shifting by three
    uint8_t reg = (second & 0b00111000) >> 3;

    // Extract R/M field by masking the upper five bits
    uint8_t rm = second & 0b00000111;

    const char *src_reg;
    const char *dest_reg;
    if (d == 0)
    {
        // Dest in R/M
        src_reg = find_reg_rm11(reg, w);
        dest_reg = find_reg_rm11(rm, w);
    }
    else
    {
        // Dest in REG
        src_reg = find_reg_rm11(rm, w);
        dest_reg = find_reg_rm11(reg, w);
    }

    printf("mov %s, %s", dest_reg, src_reg);

    REGISTER src_reg_number = register_str_to_enum(src_reg);
    REGISTER dest_reg_number = register_str_to_enum(dest_reg);
    const int16_t data = REGISTER_LUT[src_reg_number];
    const int16_t dest_prev_value = REGISTER_LUT[dest_reg_number];
    const int16_t dest_new_value = data;

    // Move data into dest register
    REGISTER_LUT[dest_reg_number] = data;

    printf(" ; %s: 0x%x->0x%x\n", dest_reg, dest_prev_value, dest_new_value);

    // Return the total size of the instruction in bytes
    return instruction_size;
}

/** Decoding function for MOV (memory to/from register). */
static inline size_t decode_mov_mem_reg(const uint8_t *buffer,
                                        const size_t &index)
{
    // Total size of the instruction in bytes
    size_t instruction_size = 0;

    uint8_t first = buffer[index];
    instruction_size++;
    uint8_t second = buffer[index + instruction_size];
    instruction_size++;

    // Extract D bit by masking all bits but the second last, then right
    // shifting by 1
    uint8_t d = (first & 0b00000010) >> 1;

    // Extract W bit by masking all bits but the last
    uint8_t w = first & 0b00000001;

    // Extract MOD field by masking the lower six bits, then right shifting by 6
    uint8_t mod = (second & 0b11000000) >> 6;

    // Extract REG field by masking all but the middle three bits, then right
    // shifting by three
    uint8_t reg = (second & 0b00111000) >> 3;

    // Extract R/M field by masking the upper five bits
    uint8_t rm = second & 0b00000111;

    const char *src;
    const char *dest;
    if (d == 0)
    {
        // Dest in R/M
        src = find_reg_rm11(reg, w);
        dest = find_rm(rm);
    }
    else
    {
        // Dest in REG
        src = find_rm(rm);
        dest = find_reg_rm11(reg, w);
    }

    const uint8_t *disp_ptr = &buffer[index + instruction_size];
    const bool direct_address = mod == 0b00 && rm == 0b110;
    int16_t displacement =
        find_displacement(mod, direct_address, disp_ptr, instruction_size);

    // Print out instruction based on the D bit
    if (d == 0)
    {
        if (direct_address)
        {
            printf("mov [%d], %s\n", displacement, src);
        }
        else if (displacement > 0)
        {
            printf("mov [%s + %d], %s\n", dest, displacement, src);
        }
        else if (displacement < 0)
        {
            // Flip sign on negative displacements so they print correctly
            printf("mov [%s - %d], %s\n", dest, -displacement, src);
        }
        else
        {
            // Leave out offset if it's zero
            printf("mov [%s], %s\n", dest, src);
        }
    }
    else
    {
        if (direct_address)
        {
            printf("mov %s, [%d]\n", dest, displacement);
        }
        else if (displacement > 0)
        {
            printf("mov %s, [%s + %d]\n", dest, src, displacement);
        }
        else if (displacement < 0)
        {
            // Flip sign on negative displacements so they print correctly
            printf("mov %s, [%s - %d]\n", dest, src, -displacement);
        }
        else
        {
            // Leave out offset if it's zero
            printf("mov %s, [%s]\n", dest, src);
        }
    }

    // Return the total size of the instruction in bytes
    return instruction_size;
}

/** Decoding function for MOV (immediate to register). */
static inline size_t decode_mov_imm_reg(const uint8_t *buffer,
                                        const size_t &index)
{
    // Total size of the instruction in bytes
    size_t instruction_size = 0;

    uint8_t first = buffer[index];
    instruction_size++;

    // Extract W bit by masking all bits but the fifth highest
    uint8_t w = (first & 0b00001000) >> 3;

    // Extract REG field by masking all but the three lowest bits
    uint8_t reg = first & 0b0000111;

    const uint8_t *data_ptr = &buffer[index + instruction_size];
    int16_t data = get_data(w, data_ptr, instruction_size);

    const char *dest_reg = find_reg_rm11(reg, w);

    printf("mov %s, %hd", dest_reg, data);

    REGISTER reg_number = register_str_to_enum(dest_reg);
    const int16_t prev_value = REGISTER_LUT[reg_number];
    const int16_t curr_value = data;

    // Move the data into the register
    REGISTER_LUT[reg_number] = data;

    printf(" ; %s: 0x%x->0x%x\n", dest_reg, prev_value, curr_value);

    // Return the total size of the instruction in bytes
    return instruction_size;
}

/** Decoding function for MOV (immediate to memory). */
static inline size_t decode_mov_imm_mem(const uint8_t *buffer,
                                        const size_t &index)
{
    // Total size of the instruction in bytes
    size_t instruction_size = 0;

    uint8_t first = buffer[index];
    instruction_size++;
    uint8_t second = buffer[index + instruction_size];
    instruction_size++;

    // Extract W bit by masking all bits but the last
    uint8_t w = first & 0b00000001;

    // Extract MOD field by masking the lower six bits, then right shifting by 6
    uint8_t mod = (second & 0b11000000) >> 6;

    // Extract R/M field by masking the upper five bits
    uint8_t rm = second & 0b00000111;

    const uint8_t *disp_ptr = &buffer[index + instruction_size];
    const bool direct_address = mod == 0b00 && rm == 0b110;
    int16_t displacement =
        find_displacement(mod, direct_address, disp_ptr, instruction_size);

    const uint8_t *data_ptr = &buffer[index + instruction_size];
    int16_t data = get_data(w, data_ptr, instruction_size);

    // MOD will never be 11 since there is no register involved here, so it's
    // fine to not check for that case
    const char *dest = find_rm(rm);

    if (w == 0)
    {
        print_mov_reg_mem(direct_address, displacement, "byte", data, dest);
    }
    else
    {
        print_mov_reg_mem(direct_address, displacement, "word", data, dest);
    }

    // Return the total size of the instruction in bytes
    return instruction_size;
}

/** Decoding function for MOV (accumulator to/from memory). */
static inline size_t decode_mov_accum_mem(const uint8_t *buffer,
                                          const size_t &index)
{
    // Total size of the instruction in bytes
    size_t instruction_size = 0;

    uint8_t first = buffer[index];
    instruction_size++;

    // Test whether it's accumulator to memory or memory to accumulator
    bool accum_to_mem = (first & 0b11111110) == 0b10100010;

    // Extract W bit by masking all bits but the last
    uint8_t w = first & 0b00000001;

    const uint8_t *address_ptr = &buffer[index + instruction_size];
    const char *src = {};
    if (w == 0)
    {
        // Address is 8 bits, use 8-bit register
        src = "al";
    }
    else
    {
        // Address is 16 bits, use 16-bit register
        src = "ax";
    }

    // Regardless of address size, the address part of the instruction always
    // takes up 16 bits in memory
    uint16_t accum_addr = *(const uint16_t *)address_ptr;
    instruction_size += 2;

    if (accum_to_mem)
    {
        printf("mov [%hd], %s\n", accum_addr, src);
    }
    else
    {
        printf("mov %s, [%hd]\n", src, accum_addr);
    }

    // Return the total size of the instruction in bytes
    return instruction_size;
}

/*******************************************************************************
 * 8086 DECODER OPCODE DECODING DATA STRUCTURES/GLOBAL VARIABLES
 ******************************************************************************/

/**
 * Pointer to a function which decodes an opcode, taking the pointer to the
 * instruction buffer and the buffer index as inputs and returning the total
 * size of the instruction in bytes.
 */
typedef size_t (*OpcodeDecodingFunction)(const uint8_t *, const size_t &);

/** Enum for indexing into the opcode lookup table. */
enum OPCODE
{
    MOV_REG_REG,
    MOV_MEM_REG,
    MOV_IMM_REG,
    MOV_IMM_MEM,
    MOV_ACCUM_MEM,
    NUM_OPCODES
};

/** Lookup table for opcode decoding functions. */
// clang-format off
constexpr OpcodeDecodingFunction OPCODE_FUNC_LUT[] = { 
    decode_mov_reg_reg, 
    decode_mov_mem_reg,
    decode_mov_imm_reg,
    decode_mov_imm_mem,
    decode_mov_accum_mem
};
// clang-format on

/*******************************************************************************
 * 8086 DECODER MAIN FUNCTIONS
 ******************************************************************************/

/**
 * The main API function for the decoder. Uses the value of the opcode given to
 * index into a lookup table of function pointers and then calls the proper
 * decoding function. Returns the total number of bytes used to increment the
 * buffer pointer with.
 */
static inline size_t decode_8086(const OPCODE opcode,
                                 const uint8_t *buffer,
                                 const size_t &index)
{
    assert(opcode < NUM_OPCODES);
    OpcodeDecodingFunction function = OPCODE_FUNC_LUT[opcode];
    size_t total_bytes = function(buffer, index);
    return total_bytes;
}

/**
 * Loads the file from disc and parses the opcodes to send off to the decoding
 * functions.
 */
int main()
{
#ifdef _MSC_VER
    // Setup the CRT automated memory leak checker
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    // Send all reports to STDOUT
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);

    // Set this to the allocation number given by the leak checker to break at
    // it
    //_CrtSetBreakAlloc(863);
#endif

    // Open binary file
    std::ifstream file("./asm/listing_0044_register_movs", std::ios::binary);

    if (!file)
    {
        printf("Error: Failed to open file.\n");
        return 1;
    }

    // Get instruction size from file
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Allocate memory for instruction buffer
    uint8_t *buffer = new uint8_t[file_size];

    // Read binary data from file
    file.read((char *)buffer, file_size);

    // Close file
    file.close();

    size_t index = 0;
    // Decode instructions one byte at a time
    while (index < file_size)
    {
        uint8_t first = buffer[index];

        // Mask the last four bits and look at the first four bits to determine
        // the opcode
        uint8_t firstfour = first & 0b11110000;
        if (firstfour == 0b10000000)
        {
            // Register/memory to/from register (100010)

            uint8_t second = buffer[index + 1];
            size_t total_bytes = 0;

            // Look at the first two bits of the second byte to determine the
            // mode
            uint8_t mod = second & 0b11000000;
            if (mod == 0b11000000)
            {
                // Register to/from register (11)
                total_bytes = decode_8086(MOV_REG_REG, buffer, index);
            }
            else
            {
                // Memory to/from register (00/01/10)
                total_bytes = decode_8086(MOV_MEM_REG, buffer, index);
            }

            index += total_bytes;
        }
        else if (firstfour == 0b10110000)
        {
            // Immediate to register (1011)
            size_t total_bytes = decode_8086(MOV_IMM_REG, buffer, index);
            index += total_bytes;
        }
        else if (firstfour == 0b11000000)
        {
            // Immediate to memory (1100011)
            size_t total_bytes = decode_8086(MOV_IMM_MEM, buffer, index);
            index += total_bytes;
        }
        else if (firstfour == 0b10100000)
        {
            // Accumulator to/from memory (1010000/1010001)
            size_t total_bytes = decode_8086(MOV_ACCUM_MEM, buffer, index);
            index += total_bytes;
        }
        else
        {
            printf("Unknown opcode.\n");
            index++;
        }
    }

    printf("\nFinal registers:\n");
    // clang-format off
    for (uint32_t register_index = 0;
         register_index < NUM_REGISTERS;
         register_index++)
    // clang-format on
    {
        int16_t val = REGISTER_LUT[register_index];
        if (val != 0)
        {
            const char *register_str =
                register_enum_to_str(REGISTER(register_index));
            printf("%s: 0x%04x\n", register_str, val);
        }
    }

    // Deallocate buffer
    delete[] buffer;

#ifdef _MSC_VER
    // Perform the leak check
    _CrtDumpMemoryLeaks();
#endif

    return 0;
}
