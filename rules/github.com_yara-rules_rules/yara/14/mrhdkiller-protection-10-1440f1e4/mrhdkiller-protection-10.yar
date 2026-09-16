import "pe"
rule MrHDKiLLeR_ProtectioN_10: PEiD
{
    strings:
        $a = { 48 51 44 2E A1 01 01 2D 11 00 8B D8 05 00 01 8B F0 BF 00 01 B9 14 00 90 F3 A4 8B CB D1 E9 B8 00 01 8B F0 8B F8 06 6A 00 07 26 8B 2E 04 00 26 FF 36 06 00 07 26 8A 76 00 6A 00 07 26 8B 2E 0C 00 26 FF 36 0E 00 07 26 8A 56 00 6A 00 07 26 8B 1E }
    condition:
        $a at pe.entry_point

}