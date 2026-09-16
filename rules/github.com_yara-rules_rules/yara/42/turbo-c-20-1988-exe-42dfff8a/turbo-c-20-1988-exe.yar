import "pe"
rule Turbo_C_20_1988_EXE: PEiD
{
    strings:
        $a = { BA 00 00 2E 89 16 00 01 B4 30 00 00 8B 2E 02 00 8B 1E 2C 00 8E DA A3 00 00 8C 06 00 00 89 1E 00 00 89 2E 00 00 C7 06 00 00 FF FF E8 00 00 C4 3E 00 00 8B C7 8B D8 B9 FF 7F 26 81 3D 38 37 75 19 26 8B 55 02 80 FA 3D 75 10 80 E6 DF FF 06 00 00 }
    condition:
        $a at pe.entry_point

}