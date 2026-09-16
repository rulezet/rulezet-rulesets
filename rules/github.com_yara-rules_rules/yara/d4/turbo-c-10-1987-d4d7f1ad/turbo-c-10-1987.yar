import "pe"
rule Turbo_C_10_1987: PEiD
{
    strings:
        $a = { BA 00 01 2E 89 16 72 01 B4 30 00 00 8B 2E 02 00 8B 1E 2C 00 8E DA A3 86 00 8C 06 84 00 89 1E 80 00 89 2E 98 00 C7 06 8A 00 FF FF 8E C3 33 C0 B9 FF 7F 8B F8 8B D8 26 81 3D 38 37 75 1D 57 51 50 B0 3D F2 AE E3 11 26 8A 05 24 DF FF 06 8A 00 3C }
    condition:
        $a at pe.entry_point

}