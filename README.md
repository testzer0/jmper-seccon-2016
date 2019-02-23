# jmper-seccon-2016

jmper is the binary, sploit4.py is the exploit. Uses hardcoded offsets which may be different for your system.

# Synopsis of steps

1) One byte overwrite in new_memo which overwrites LSB of student name ptr.

2) Create two students, overwrite student1's name to point at student 2's name ptr and change it whenever needed. Use student 2 for R/W.

3) Using this arbitrary R/W primitive leak lomgjmp stored values and leak stack address and libc.

4) Write ROP chain onto stack using arbitrary write and trigger longjmp to jump to shellcode.

5) Spawn shell.
