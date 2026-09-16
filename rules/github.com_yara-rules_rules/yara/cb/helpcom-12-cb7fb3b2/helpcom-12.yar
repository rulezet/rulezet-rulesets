import "pe"
rule HelpCOM_12: PEiD
{
    strings:
        $a = { FC BE 81 00 AC 3C 20 74 FB 3C 3F 74 1A 3C 2F 75 05 AC 3C 3F 74 11 A1 00 00 A3 00 01 A0 00 00 A2 02 01 BB 00 01 FF E3 BA 00 00 B4 09 CD 21 C3 40 65 63 68 6F 20 6F 66 66 0D 0A 69 66 20 25 31 2E 3D 3D 2E 20 67 6F 74 6F 20 65 6E 64 65 0D 0A 66 }
    condition:
        $a at pe.entry_point

}