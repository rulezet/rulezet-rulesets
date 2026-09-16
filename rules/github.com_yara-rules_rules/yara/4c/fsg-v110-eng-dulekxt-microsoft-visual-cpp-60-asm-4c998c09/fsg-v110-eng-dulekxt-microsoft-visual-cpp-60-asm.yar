import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_ASM_: PEiD
{
    strings:
        $a = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
    condition:
        $a at pe.entry_point

}