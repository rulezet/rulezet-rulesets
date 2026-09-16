rule BruteRatelSyscall
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Syscall Bypass"
        cape_options = "sysbp=$syscall1+6,sysbp=$syscall2+8"
    strings:
        $syscall1 = {49 89 CA 4? 89 ?? (41 FF|FF)}
        $syscall2 = {49 89 CA 48 8B 44 24 ?? FF 64 24}
    condition:
        all of them
}