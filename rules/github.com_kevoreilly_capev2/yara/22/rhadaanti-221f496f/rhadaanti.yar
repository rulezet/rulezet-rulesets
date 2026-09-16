rule RhadaAnti
{
    meta:
        author = "kevoreilly"
        cape_options = "bp0=$anti,action0=jmp,count=0,ntdll-protect=0,dump-limit=0"
    strings:
        $anti = {74 0E FF 75 ?? 8D 45 ?? 50 E8 [4] 59 59 8D 45 ?? 50 56 68 04 01 00 00}
    condition:
        all of them
}