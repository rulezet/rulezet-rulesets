import "pe"
rule Trap_114a: PEiD
{
    strings:
        $a = { B9 E8 03 EB 03 90 CD 20 E2 F9 8C D1 BA 99 CB 8E D2 33 D2 8E D1 8B CA 33 D2 B9 00 05 EB 03 90 CD 20 81 F9 E2 03 74 33 83 C1 FE 83 C2 01 EB ED EB FE EB 25 0D 0A 09 09 09 20 C4 C4 C4 C4 C4 C4 C4 C4 5B 20 54 52 41 50 20 31 2E 31 34 20 5D C4 C4 }
    condition:
        $a at pe.entry_point

}