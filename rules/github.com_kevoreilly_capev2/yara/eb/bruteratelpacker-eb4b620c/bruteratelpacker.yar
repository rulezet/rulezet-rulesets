rule BruteRatelPacker
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Outer Encryption Layer"
        cape_options = "bp1=$outer*,action1=scan,count=0"
    strings:
        $outer = {83 45 F8 01 81 7D F8 FF 00 00 00 7E ?? 83 45 FC 01 8B 45 FC 3B 45 ?? 7E ?? 48}
        $inner = {88 E3 32 1C 0E 88 5C 15 00 48 8D 49 01 48 8D 52 01 38 C1 76 ?? 48 01 CE EB ?? FF}
        $date = {48 8B 17 48 85 D2 0F 85 [2] 00 00 8B 47 08 85 C0 0F 85 [2] 00 00}
    condition:
        ($outer) and not ($inner) and not ($date)
}