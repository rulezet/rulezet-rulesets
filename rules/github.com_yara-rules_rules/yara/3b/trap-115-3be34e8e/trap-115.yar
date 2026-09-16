import "pe"
rule Trap_115: PEiD
{
    strings:
        $a = { B9 E8 03 EB 03 90 CD 20 E2 F9 8C D1 BA 99 CB 8E D2 33 D2 8E D1 8B CA 33 D2 B9 00 05 EB 03 90 CD 20 81 F9 E2 03 74 0C 83 C1 FE 83 C2 01 EB ED EB FE CD 78 E8 0C 00 CD 21 EB 73 90 EA 00 00 FF FF EB F9 FA 66 8C E3 66 B8 00 00 01 00 8E E0 66 8C }
    condition:
        $a at pe.entry_point

}