rule BruteRatelDate
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Date Check Bypass"
        cape_options = "clear,bp1=$inner*,action1=scan,bp2=$date+6,action2=skip,count=0"
    strings:
        $inner = {88 E3 32 1C 0E 88 5C 15 00 48 8D 49 01 48 8D 52 01 38 C1 76 ?? 48 01 CE EB ?? FF}
        $date = {48 8B 17 48 85 D2 0F 85 [2] 00 00 8B 47 08 85 C0 0F 85 [2] 00 00}
    condition:
        any of them
}