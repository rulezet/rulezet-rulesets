import "pe"
rule Trap_113_EXE: PEiD
{
    strings:
        $a = { 8C D1 BA 99 CB 8E D2 33 D2 8E D1 8B CA EB 05 90 20 73 6B 00 BA 16 01 B4 4E CD 21 B9 E8 03 EB 03 90 CD 20 E2 F9 33 D2 B9 00 05 EB 03 90 CD 20 81 F9 E2 03 74 66 83 C1 FE 83 C2 01 EB ED 54 20 }
    condition:
        $a at pe.entry_point

}