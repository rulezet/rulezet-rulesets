import "pe"
rule Turbo_C_20_1988_COM: PEiD
{
    strings:
        $a = { 8C CA 2E 89 16 D6 02 B4 30 CD 21 8B 2E 02 00 8B 1E 2C 00 8E DA A3 00 00 8C 06 00 00 89 1E 00 00 89 2E 00 00 C7 06 00 00 FF FF E8 13 01 C4 3E 00 00 8B C7 8B D8 B9 FF 7F 26 81 3D 38 37 75 19 26 8B 55 02 80 FA 3D 75 10 80 E6 DF FF 06 00 00 80 }
    condition:
        $a at pe.entry_point

}