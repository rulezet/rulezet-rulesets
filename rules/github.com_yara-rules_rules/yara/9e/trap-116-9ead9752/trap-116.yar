import "pe"
rule Trap_116: PEiD
{
    strings:
        $a = { 8C D0 BB 99 CB 90 8E D3 33 DB 8E D0 8B C3 EB 0F 90 66 0F BD C3 0F 06 66 0F BD C3 66 0F BC C3 B9 7D 04 EB 03 90 CD 20 E2 F9 33 D2 B9 00 05 EB 03 90 CD 20 81 F9 E2 03 74 0E 90 90 83 C1 FE 83 C2 01 EB EB EB FE CD 78 0F 21 E9 0F 21 DB 66 03 CB }
    condition:
        $a at pe.entry_point

}