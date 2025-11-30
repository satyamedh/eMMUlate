/**
 * keys.c
 * TI Nspire CX II BootROM Key extraction exploit
 * 
 * Pioneered by @Satyamedh
 * Assistance by @Vogtinator, @Adriweb and @sasdallas
 */

#include <libndls.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "qrcode/qrcode.h"

static inline uint32_t get_ttbr0(void) {
    uint32_t val;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(val));
    return val;
}

static inline void set_ttbr0(uint32_t val) {
    asm volatile("mcr p15, 0, %0, c2, c0, 0" :: "r"(val));
}

static inline uint32_t get_dacr(void) {
    uint32_t val;
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(val));
    return val;
}

static inline void set_dacr(uint32_t val) {
    asm volatile("mcr p15, 0, %0, c3, c0, 0" :: "r"(val));
}

static inline void tlb_invalidate(void) {
    asm volatile("mcr p15, 0, %0, c8, c7, 0" :: "r"(0));
    asm volatile("mcr p15, 0, %0, c7, c10, 4" :: "r"(0)); 
}

static inline void clean_dcache_range(uint32_t start, uint32_t end) {
    uint32_t addr;
    for (addr = start; addr < end; addr += 32) {
        asm volatile("mcr p15, 0, %0, c7, c10, 1" :: "r"(addr));
    }
    asm volatile("mcr p15, 0, %0, c7, c10, 4" :: "r"(0));
}

uint8_t page_table_buffer[0x8000]; 
uint8_t vector_buffer[0x4000]; 
uint8_t cpta_vectors_buffer[0x1000]; // 4KB for vector page table
uint8_t cpta_stack_buffer[0x1000]; // 4KB for stack page table

// Global state for key extraction
uint32_t key_params[] = {0x27, 0x3d, 0x25, 0x2d};
volatile int current_key_idx = 0;

// Extracted keys: 4 sets, 6 values each (des_regs[2..7])
uint32_t extracted_keys[4][6];

int intmask = 0;

void __attribute__((noreturn)) trigger_next_key(void);
void call_rom39c(uint32_t sram_stack, uint32_t r2_val);

typedef enum {
    RESET,
    UD_INSTRUCTION,
    SUPERVISOR,
    PREFETCH,
    DATA_ABORT, // we want this one
    RSRVD,
    IRQ,
    FIQ
} EXCEPTION_TYPE;

void c_handler(EXCEPTION_TYPE type, uint32_t lr, uint32_t sp) {
    if (type == DATA_ABORT) {
        volatile uint32_t* des_regs = (volatile uint32_t*)0x13010000;
        for (int i = 0; i < 6; i++) {
            extracted_keys[current_key_idx][i] = des_regs[2 + i];
        }

        printf("Key Set %d:\n", current_key_idx + 1);
        printf("Key 1 R: 0x%08lX\n", extracted_keys[current_key_idx][0]);
        printf("Key 1 L: 0x%08lX\n", extracted_keys[current_key_idx][1]);
        printf("Key 2 R: 0x%08lX\n", extracted_keys[current_key_idx][2]);
        printf("Key 2 L: 0x%08lX\n", extracted_keys[current_key_idx][3]);
        printf("Key 3 R: 0x%08lX\n", extracted_keys[current_key_idx][4]);
        printf("Key 3 L: 0x%08lX\n", extracted_keys[current_key_idx][5]);

        current_key_idx++;
        trigger_next_key();
    } else {
        char *exception = "UNKNOWN";
        switch (type) {
            case RESET: exception = "RESET"; break;
            case UD_INSTRUCTION: exception = "UNDEFINED INSTRUCTION"; break;
            case SUPERVISOR: exception = "SUPERVISOR"; break;
            case PREFETCH: exception = "PREFETCH ABORT"; break;
            case DATA_ABORT: exception = "DATA ABORT"; break;
            case RSRVD: exception = "RESERVED"; break;
            case IRQ: exception = "IRQ"; break;
            case FIQ: exception = "FIQ"; break;
        }

        uint32_t dfsr, dfar;
        asm volatile("mrc p15, 0, %0, c5, c0, 0" : "=r"(dfsr));
        asm volatile("mrc p15, 0, %0, c6, c0, 0" : "=r"(dfar));

        printf("\n!!! EXCEPTION: %s !!!\nLR: 0x%08lX\nSP: 0x%08lX\n", exception, lr, sp);
        printf("DFSR: 0x%08lX  DFAR: 0x%08lX\n", dfsr, dfar);
    }
    while(1);
}

// Macros for naked handlers
#define EXCEPTION_HANDLER(name, str) \
void __attribute__((naked)) name(void) { \
    asm volatile( \
        "ldr sp, =0xFFFF1000\n" /* Use top of our vector page as temp stack (High Vectors) */ \
        "stmfd sp!, {r0-r3, lr}\n" \
        "mov r0, %0\n" \
        "mov r1, lr\n" \
        "mov r2, sp\n" \
        "bl c_handler\n" \
        "ldmfd sp!, {r0-r3, pc}^" \
        :: "r"((uint32_t)str) \
    ); \
}

EXCEPTION_HANDLER(reset_handler, RESET)
EXCEPTION_HANDLER(undef_handler, UD_INSTRUCTION)
EXCEPTION_HANDLER(svc_handler, SUPERVISOR)
EXCEPTION_HANDLER(prefetch_handler, PREFETCH)
EXCEPTION_HANDLER(data_handler, DATA_ABORT)
EXCEPTION_HANDLER(reserved_handler, RSRVD)
EXCEPTION_HANDLER(irq_handler, IRQ)
EXCEPTION_HANDLER(fiq_handler, FIQ)



void perform_exploit_setup(void) {
    printf("Performing exploit setup...\n");

	// these are the observed conditions that 0x39c is in when called via bootloader.
	volatile uint32_t *usb_top = (volatile uint32_t *)0xB0000000;
	usb_top[0x100 / 4] = 0;

	usb_top[0x1C0 / 4] = 0;

	volatile uint32_t *usb_bottom = (volatile uint32_t *)0xB4000000;
	usb_bottom[0x100 / 4] = 0;

	usb_bottom[0x1C0 / 4] = 0;

	volatile uint32_t *sha_base = (volatile uint32_t *)0xCC000000;
	sha_base[2] = 0x500;

    volatile uint32_t *dc_base = (volatile uint32_t *)0xDC000000;
    volatile uint32_t *bc_base = (volatile uint32_t *)0xBC000000;

    asm volatile (
        "1: mrc p15, 0, pc, c7, c14, 3 \n\t"
        "bne 1b \n\t"
        ::: "cc"
    );
    asm volatile("mcr p15, 0, %0, c7, c10, 4" :: "r"(0)); 
    asm volatile("mcr p15, 0, %0, c7, c5, 0" :: "r"(0));  

    asm volatile (
        "mrs r0, cpsr \n\t"
        "bic r0, r0, #0x1f \n\t"
        "orr r0, r0, #0x13 \n\t"
        "msr cpsr_cf, r0 \n\t"
        ::: "r0"
    );

    dc_base[5] = 0xFFFFFFFF;

    while (bc_base[7] != 0);

    bc_base[9] &= ~1;

    asm volatile (
        "1: mrc p15, 0, pc, c7, c14, 3 \n\t"
        "bne 1b \n\t"
        ::: "cc"
    );

    uint32_t sctlr;
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr &= ~((1 << 12) | (1 << 2)); 
    asm volatile("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));

    uint32_t c15_val;
    asm volatile("mrc p15, 0, %0, c15, c0, 0" : "=r"(c15_val));
    c15_val |= (1 << 16);
    asm volatile("mcr p15, 0, %0, c15, c0, 0" :: "r"(c15_val));

    asm volatile("mrc p15, 0, %0, c15, c0, 0" : "=r"(c15_val));
    c15_val |= (1 << 16);
    asm volatile("mcr p15, 0, %0, c15, c0, 0" :: "r"(c15_val));

    asm volatile (
        "mrs r0, cpsr \n\t"
        "orr r0, r0, #0xc0 \n\t"
        "msr cpsr_cxsf, r0 \n\t"
        ::: "r0"
    );

    dc_base[3] = 0xFFFFFFFF;
    dc_base[67] = 0xFFFFFFFF;

    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr &= ~((1 << 12) | (1 << 2));
    asm volatile("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));

    asm volatile("mcr p15, 0, %0, c7, c7, 0" :: "r"(0));

    asm volatile (
        "mrs r0, cpsr \n\t"
        "orr r0, r0, #0xc0 \n\t"
        "msr cpsr_cxsf, r0 \n\t"
        ::: "r0"
    );

    bc_base[9] = 0;

    printf("Exploit setup complete.\n");
}

__attribute__((naked))
void call_rom39c(uint32_t __attribute__((unused)) sram_stack, uint32_t __attribute__((unused)) r2_val) {
    asm volatile(
        // r0 = sram_stack
        // r1 = r2_val
        
        "mov r12, r0                \n\t"   // r12 = sram_stack
        
        // Save caller registers on *current* stack
        "stmfd sp!, {r4-r11, lr}    \n\t"

        // Save old SP
        "mov   r4, sp               \n\t"

        // Switch to trap stack
        "mov   sp, r12              \n\t"

        // Save old SP on trap stack
        "stmfd sp!, {r4}            \n\t"

        // Setup ROM args
        "mov r2, r1                 \n\t"   // r2 = r2_val
        "mov r0, #0x5               \n\t"
        "mov r1, #0x5               \n\t"
        "mov r3, #0x1               \n\t"

        // Call ROM 0x39C
        "ldr lr, =0x0000039C        \n\t"
        "blx lr                     \n\t"

        // Restore SP
        "ldmfd sp!, {r4}            \n\t"
        "mov   sp, r4               \n\t"

        // Restore caller registers and return
        "ldmfd sp!, {r4-r11, lr}    \n\t"
        "bx lr                      \n\t"
    );
}

void print_all_keys(void) {
   printf("\n---- All Extracted Keys ----\n");

    // Header row with set numbers + r2 values
    for (int set = 0; set < 4; set++) {
        printf(" %d (%02lX)  ", set + 1, key_params[set]);
    }
    printf("\n");

    // Print each of the 6 keys per set, row by row across all sets
    for (int row = 0; row < 6; row++) {
        for (int set = 0; set < 4; set++) {
            printf("%08lX ", extracted_keys[set][row]);
        }
        printf("\n");
    }

    printf("---- End Extracted Keys ----\n");
    printf("\nYou might want to write these keys down or take a\npicture.\n\n");
    printf("Press any key to move to QR code generation...\n");
}




void genqrcode() {
    printf("QR code creation in progress... This will take a sec\n\n");
    printf("Scanning the above QR code will take you to a website\nBoth QR codes are the same, scan either one.\n\n");
    printf("The website will inject the keys into a BootROM dump you made using polydumper\n\n");
    printf("Once finished, you can reboot by pressing any key.\n");

    QRCode qrcode;
    uint8_t qrcodeBytes[qrcode_getBufferSize(12)];

    // generate the string using extracted keys
    char qrdata[360];
    // there's a total of 4 sets keys, each with 6 values
    sprintf(qrdata, "https://satyamedh.github.io/eMMUlate_injector?l11=%08lX&r11=%08lX&l12=%08lX&r12=%08lX&l13=%08lX&r13=%08lX&l21=%08lX&r21=%08lX&l22=%08lX&r22=%08lX&l23=%08lX&r23=%08lX&l31=%08lX&r31=%08lX&l32=%08lX&r32=%08lX&l33=%08lX&r33=%08lX&l41=%08lX&r41=%08lX&l42=%08lX&r42=%08lX&l43=%08lX&r43=%08lX",
        extracted_keys[0][1], extracted_keys[0][0], extracted_keys[0][3], extracted_keys[0][2], extracted_keys[0][5], extracted_keys[0][4],
        extracted_keys[1][1], extracted_keys[1][0], extracted_keys[1][3], extracted_keys[1][2], extracted_keys[1][5], extracted_keys[1][4],
        extracted_keys[2][1], extracted_keys[2][0], extracted_keys[2][3], extracted_keys[2][2], extracted_keys[2][5], extracted_keys[2][4],
        extracted_keys[3][1], extracted_keys[3][0], extracted_keys[3][3], extracted_keys[3][2], extracted_keys[3][5], extracted_keys[3][4]
    );

    qrcode_initText(&qrcode, qrcodeBytes, 12, ECC_LOW, qrdata);
    
    uint8_t *vram = (uint8_t *)0xA8000000;

    // CONFIG
    int scale = 4;
    int border_thickness = 1;
    int off_x = 20; 
    int off_y = 20; 

    int modules = qrcode.size + border_thickness * 2;  // full module grid incl. border

    // DRAW BORDER + QR
    for (int y = 0; y < modules; y++) {
        for (int x = 0; x < modules; x++) {

            // Determine if this module is border or QR data
            bool is_border =
                (x < border_thickness) ||
                (y < border_thickness) ||
                (x >= qrcode.size + border_thickness) ||
                (y >= qrcode.size + border_thickness);

            uint8_t color;

            if (is_border) {
                color = 255;
            } else {
                // map back to actual QR code coords
                int qr_x = x - border_thickness;
                int qr_y = y - border_thickness;
                color = qrcode_getModule(&qrcode, qr_x, qr_y) ? 0 : 255;
            }

            // Draw the scaled pixels
            for (int dy = 0; dy < scale; dy++) {
                for (int dx = 0; dx < scale; dx++) {
                    int px = off_x + (x * scale + dx);
                    int py = off_y + (y * scale + dy);
                    vram[py * 320 + px] = color;
                }
            }
        }
    }
}


BOOL _any_key_pressed(void) {
	volatile int *addr;
	// touchpad_report_t report;
	// touchpad_scan(&report);
	// if (report.pressed) return TRUE; // uses an SWI, hence avoiding it
	for (addr = (volatile int*) 0x900E0010; addr < (volatile int *)(0x900E0000 + 0x20); addr += 1) {
		if (*addr)
			return TRUE;
	}
	return FALSE;
}

void _wait_no_key_pressed(void) {
	while (_any_key_pressed());
}

void _wait_key_pressed(void) {
	_wait_no_key_pressed();
	while (!_any_key_pressed());
}

void calc_reboot(void) {
    volatile unsigned int *wdload = (volatile unsigned int*)0x90060000;
	volatile unsigned int *wdcontrol = (volatile unsigned int*)0x90060008;
	volatile unsigned int *wdlock = (volatile unsigned int*)0x90060C00;

	*wdlock = 0x1ACCE551; // unlock the watchdog
	*wdload = 0x1000; // set the timeout
	*wdcontrol = 0x03; // enable the watchdog and reset on timeout

	while (1);
}

void clear_screen(){
    for (int i = 0; i < 25; i++) printf("\n");
}

void __attribute__((noreturn)) trigger_next_key(void) {
    if (current_key_idx >= 4) {
        // finished!
        clear_screen();
        printf("All keys extracted.\n");
        print_all_keys();
        _wait_key_pressed();
        clear_screen();
        genqrcode();
        _wait_key_pressed();
        calc_reboot();
    }
    
    uint32_t r2_val = key_params[current_key_idx];

    // Switch to SVC mode and reset stack
    asm volatile (
        "mrs r0, cpsr \n\t"
        "bic r0, r0, #0x1f \n\t"
        "orr r0, r0, #0x13 \n\t" // SVC mode
        "msr cpsr_c, r0 \n\t"
        "mov sp, %0 \n\t"
        :: "r"(0xA4004000) : "r0", "memory"
    );
    
    uint32_t trap_stack = 0x18000020;
    call_rom39c(trap_stack, r2_val);
    
    // Should not be reached if trap works
    printf("Returned from ROM function (unexpectedly)...\n");
    while(1);
}

void __attribute__((noreturn)) exploit_payload(void) {
    perform_exploit_setup();
    current_key_idx = 0;
    trigger_next_key();
}

int main(void) {

    printf("\
 ___ __ __ __ __ _  _ _    __ _____ ___  \n\
| __|  V  |  V  | || | |  /  \\_   _| __| \n\
| _|| \\_/ | \\_/ | \\/ | |_| /\\ || | | _|  \n\
|___|_| |_|_| |_|\\__/|___|_||_||_| |___| \n\n");

    printf("eMMUlate v1 by Satyamedh Hulyalkar(@satyamedh)\n\n\n");
    printf("TI Nspire CX II BootROM Key Extraction Exploit\n\n");
    printf("This exploit will let you emulate a TI Nspire CX II\nusing firebird\n\n");
    printf("You'll also need a keyless BootROM dump made using \npolydumper\n\n");
    printf("Press any key to begin...\n");
    _wait_key_pressed();
    
    // we're about to mess with OS so malloc() won't work, stdout needs to be unbuffered
    setbuf(stdout, NULL); 

    // interrupts must be disabled
    intmask = TCT_Local_Control_Interrupts(-1); 

    printf("Starting MMU setup...\n");

    uint32_t pt_addr = ((uint32_t)page_table_buffer + 0x3FFF) & ~0x3FFF;
    uint32_t *page_table = (uint32_t *)pt_addr;

    uint32_t vec_addr = ((uint32_t)vector_buffer + 0xFFF) & ~0xFFF; 
    uint32_t *vectors = (uint32_t *)vec_addr;

    uint32_t cpta_vec_addr = ((uint32_t)cpta_vectors_buffer + 0x3FF) & ~0x3FF;
    uint32_t *coarse_vec_table = (uint32_t *)cpta_vec_addr;

    uint32_t cpta_stack_addr = ((uint32_t)cpta_stack_buffer + 0x3FF) & ~0x3FF;
    uint32_t *coarse_stack_table = (uint32_t *)cpta_stack_addr;

    // build vector table
    printf("Setting up vector table at 0x%08lX...\n", vec_addr);
    for (int i = 0; i < 8; i++) vectors[i] = 0xE59FF018;
    vectors[8] = (uint32_t)reset_handler;
    vectors[9] = (uint32_t)undef_handler;
    vectors[10] = (uint32_t)svc_handler;
    vectors[11] = (uint32_t)prefetch_handler;
    vectors[12] = (uint32_t)data_handler;
    vectors[13] = (uint32_t)reserved_handler;
    vectors[14] = (uint32_t)irq_handler;
    vectors[15] = (uint32_t)fiq_handler;

    // build a new page table
    printf("Setting up page table at 0x%08lX...\n", pt_addr);
    memset(page_table, 0, 16384);
    memset(coarse_vec_table, 0, 1024);
    memset(coarse_stack_table, 0, 1024);

    // keep BR mapping intact
    page_table[0] = (0x00000000 & 0xFFF00000) | (0b11 << 10) | (0 << 5) | 0 | 0b10;
    
    // identity map 0x10000000 - 0x14000000
    for (uint32_t addr = 0x10000000; addr < 0x14000000; addr += 0x100000) {
        uint32_t idx = addr >> 20;

        uint32_t cb = (1 << 3) | (1 << 2);
        page_table[idx] = (addr & 0xFFF00000) | (0b11 << 10) | (0 << 5) | cb | 0b10;
    }

    // map some additional peripherals
    uint32_t a0_idx = 0xA0000000 >> 20;
    page_table[a0_idx] = (0xA0000000 & 0xFFF00000) | (0b11 << 10) | (0 << 5) | 0 | 0b10;

    uint32_t a4_idx = 0xA4000000 >> 20;
    page_table[a4_idx] = (0xA4000000 & 0xFFF00000) | (0b11 << 10) | (0 << 5) | 0 | 0b10;

    for (uint32_t addr = 0x90000000; addr < 0x91000000; addr += 0x100000) {
        uint32_t idx = addr >> 20;
        page_table[idx] = (addr & 0xFFF00000) | (0b11 << 10) | (0 << 5) | 0 | 0b10;
    }

    uint32_t periphs[] = {
        0xA8000000, 
        0xB0000000, 
        0xB4000000, 
        0xB8000000, 
        0xBC000000, 
        0xC0000000, 
        0xCC000000, 
        0xDC000000,
    };
    for (unsigned int i = 0; i < sizeof(periphs)/sizeof(periphs[0]); i++) {
        uint32_t addr = periphs[i];
        uint32_t idx = addr >> 20;
        page_table[idx] = (addr & 0xFFF00000) | (0b11 << 10) | (0 << 5) | 0 | 0b10;
    }

    page_table[0xFFF] = (cpta_vec_addr & 0xFFFFFC00) | (0 << 5) | 0b01;
    coarse_vec_table[0xF0] = (vec_addr & 0xFFFFF000) | (0xFF << 4) | (0 << 3) | (0 << 2) | 0b10;

    // we will change the triple-DES key engine mapping to point to 0x13000000 instead of the MMIO 0xc8000000
    // this will trick 0x39c into writing into a readable portion of memory
    // the triple-DES engine is not readable
    uint32_t des_va_idx = 0xC8000000 >> 20;
    page_table[des_va_idx] = (0x13000000 & 0xFFF00000) | (0b11 << 10) | (0 << 5) | 0 | 0b10;

    page_table[0x180] = (cpta_stack_addr & 0xFFFFFC00) | (0 << 5) | 0b01;

    for (int i = 0; i < 16; i++) {
        coarse_stack_table[i] = 0x13EF0FFD;
    }


    printf("Activating new MMU configuration...\n");
    
    // clean caches
    clean_dcache_range(pt_addr, pt_addr + 16384);
    clean_dcache_range(cpta_vec_addr, cpta_vec_addr + 1024);
    clean_dcache_range(cpta_stack_addr, cpta_stack_addr + 1024);
    clean_dcache_range(vec_addr, vec_addr + 4096);

    // set new config
    set_ttbr0(pt_addr);
    set_dacr(0x3); 

    // high vector enable
    uint32_t sctlr;
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(sctlr));
    sctlr |= (1 << 13) | (1 << 0);
    asm volatile("mcr p15, 0, %0, c1, c0, 0" :: "r"(sctlr));

    tlb_invalidate();

    printf("MMU setup complete. High Vectors enabled.\n");

    printf("Switching stack and jumping to payload...\n");

    // fire!
    asm volatile (
        "mov sp, %0 \n\t"              
        "bx %1 \n\t"                   
        :: "r"(0xA4004000), "r"(exploit_payload)
        : "memory", "cc"
    );

    while(1);
    return 0;
}