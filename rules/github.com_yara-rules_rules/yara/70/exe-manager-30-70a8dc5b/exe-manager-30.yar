import "pe"
rule EXE_Manager_30: PEiD
{
    strings:
        $a = { B4 30 1E 06 CD 21 2E A3 08 00 BF 0A 00 B9 89 0A 33 C0 2E 03 05 47 E2 FA 2E 3B 06 06 00 74 09 B8 07 0E CD 10 33 C0 50 CB BF 0A 00 B9 45 05 2E 8B 16 04 00 FA 33 C0 8E C0 26 FF 36 0C 00 26 FF 36 0E 00 26 C7 06 0C 00 45 01 26 8C 0E 0E 00 2E 89 }
    condition:
        $a at pe.entry_point

}