import "pe"
rule HackStop_112_EXE: PEiD
{
    strings:
        $a = { 52 1E B4 30 CD 21 86 E0 3D FF 02 73 02 CD 20 0E 1F B4 09 E8 03 00 24 24 EA 5A CD 21 1F 5A 53 BB EB 04 5B EB FB 9A E8 7B 06 55 FA 8B EC C7 46 FE 00 00 8B 46 FE 50 9C 16 17 9D FB 58 A9 00 01 74 06 B0 FF B4 4C CD 21 5D E8 41 00 8D E8 E6 06 11 }
    condition:
        $a at pe.entry_point

}