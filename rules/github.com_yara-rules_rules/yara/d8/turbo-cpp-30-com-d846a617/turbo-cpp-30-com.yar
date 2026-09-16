import "pe"
rule Turbo_Cpp_30_COM: PEiD
{
    strings:
        $a = { 8C CA 2E 89 16 00 03 B4 30 CD 21 8B 2E 02 00 8B 1E 2C 00 8E DA A3 00 00 8C 06 00 00 89 1E 00 00 89 2E 00 00 E8 00 01 C4 3E 00 00 8B C7 8B D8 B9 FF 7F FC F2 AE E3 61 43 26 38 05 75 F6 80 CD 80 F7 D9 89 0E 00 00 B9 01 00 D3 E3 83 C3 08 83 E3 }
    condition:
        $a at pe.entry_point

}