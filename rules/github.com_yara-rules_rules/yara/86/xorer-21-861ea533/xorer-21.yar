import "pe"
rule XoReR_21: PEiD
{
    strings:
        $a = { BA 00 00 B9 48 20 51 B0 F5 E6 60 FA B4 30 CD 21 3C 02 73 05 33 C0 06 50 CB BF 00 00 8B 36 02 00 59 E2 E3 BB 00 00 90 FC 33 C0 80 EF 9D 81 FB 00 00 74 03 43 2A 17 30 15 47 40 FE C2 86 D6 02 D6 3D 81 01 75 E8 FB 27 EB 13 31 69 AA 78 DF E2 C6 }
    condition:
        $a at pe.entry_point

}