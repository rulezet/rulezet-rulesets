import "pe"
rule XoReR_20: PEiD
{
    strings:
        $a = { BA 00 00 B9 48 20 51 B8 FF FF E7 21 B4 30 CD 21 3C 02 73 05 33 C0 06 50 CB BF 00 00 8B 36 02 00 59 E2 E3 81 C3 00 00 FC 33 C0 80 EF 9D 81 FB 00 00 74 03 43 2A 17 30 15 47 40 FE C2 86 D6 02 D6 3D 80 01 75 E8 FA 27 EB 13 31 B7 65 6A 8A 1E BC }
    condition:
        $a at pe.entry_point

}