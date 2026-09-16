import "pe"
rule HackStop_100_EXE: PEiD
{
    strings:
        $a = { B4 30 CD 21 86 E0 3D 00 03 73 06 B0 FF B4 4C CD 21 50 B8 EB 04 58 EB FB 9A B8 00 33 CD 21 50 E8 1F 04 8D B2 00 B8 01 33 CD 21 50 B8 EB 06 58 EB FB 66 38 12 E8 0A 04 8D EB 02 CA 92 50 55 52 8C D2 FA 50 B8 EB 04 58 EB FB 9A 8C C8 8E D0 EB 02 }
    condition:
        $a at pe.entry_point

}