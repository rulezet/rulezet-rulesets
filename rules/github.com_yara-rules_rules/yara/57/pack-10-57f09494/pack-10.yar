import "pe"
rule Pack_10: PEiD
{
    strings:
        $a = { EB 08 00 00 00 00 00 00 00 00 2E 8C 1E 06 00 2E 8C 06 08 00 8C C3 83 C3 10 8C C8 8E D8 BE 52 00 FC AD 3D FF FF 75 0B AD 3D FF FF 74 0C 03 C3 8E C0 AD 8B F8 26 01 1D EB E8 2E 8E 06 08 00 2E 8E 1E 06 00 8B C3 2E 03 06 04 00 50 2E A1 02 00 50 }
    condition:
        $a at pe.entry_point

}