import "pe"
rule V_Load_09: PEiD
{
    strings:
        $a = { 33 F6 2E F6 06 B0 06 FF 74 12 0E 58 8B D8 81 E3 00 F0 75 08 B1 04 D3 E0 2B F0 D3 EE 06 5B 0E 58 2B C3 B1 04 BB 3A 07 8B D3 D3 EB 81 E2 0F 00 74 01 43 2B F3 7D 02 03 F3 03 D8 03 DE B8 00 4A CD 21 73 04 B4 4C CD 21 A1 2C 00 2E A3 0A 07 2E 8C }
    condition:
        $a at pe.entry_point

}