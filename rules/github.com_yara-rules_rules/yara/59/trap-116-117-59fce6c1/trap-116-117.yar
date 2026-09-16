import "pe"
rule Trap_116_117: PEiD
{
    strings:
        $a = { 8C D0 BB 99 CB 8E D3 33 C9 8E D0 B9 7D 04 EB 03 90 CD 20 E2 F9 33 D2 E5 21 50 B9 00 05 EB 03 90 CD 20 81 F9 E2 03 74 0E 90 90 83 C1 FE 83 C2 01 EB EB FA EB FE F4 FA B8 FE 00 E7 21 58 E7 21 66 8C E3 66 B8 00 00 01 00 8E E0 66 8C E0 8E E3 66 }
    condition:
        $a at pe.entry_point

}