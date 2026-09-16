import "pe"
rule Thinstall_V2736_Jitit: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 58 BB F3 1C 00 00 2B C3 50 68 00 00 40 00 68 00 26 00 00 68 CC 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 }
    condition:
        $a at pe.entry_point

}