import "pe"
rule CRK_Compiler_120: PEiD
{
    strings:
        $a = { 2F 4D 47 2F EB 04 00 00 00 00 C8 08 00 00 E8 00 00 0E 07 C6 46 FE 00 E8 00 00 E8 00 00 8B 0E 00 00 E3 02 EB 03 E9 D4 00 2B C0 89 46 F8 B8 00 00 89 46 FC C7 46 FA 00 00 51 BA 00 00 F6 06 00 07 01 74 03 BA 00 00 E8 B5 00 8B 56 FC BB 0F 00 E8 }
    condition:
        $a at pe.entry_point

}