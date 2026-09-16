import "pe"
rule FSG_v110_dulekxt_Microsoft_Visual_Cpp_60_70: PEiD
{
    strings:
        $a = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
    condition:
        $a at pe.entry_point

}