import "pe"
rule Immun_12_registered_EXE: PEiD
{
    strings:
        $a = { 50 53 51 52 56 57 1E 06 2E 8B 0E D3 07 E3 1E 1E 06 D1 E1 8C C8 8E D8 8E C0 BE D5 07 BF 6D 08 8B D1 4A D1 E2 03 F2 03 FA FD F3 A5 07 1F B4 30 CD 21 2E A2 63 01 3C 03 72 54 1E 33 C0 8E D8 80 3E FD 04 49 C6 06 FD 04 00 1F 74 42 8E 1E 2C 00 8C }
    condition:
        $a at pe.entry_point

}