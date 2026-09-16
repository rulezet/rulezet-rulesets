import "pe"
rule EXE_Manager_32: PEiD
{
    strings:
        $a = { B4 30 1E 06 CD 21 2E A3 08 00 BF 0A 00 B9 F6 0B 33 C0 2E 03 05 47 E2 FA 2E 3B 06 06 00 74 09 B8 07 0E CD 10 33 C0 50 CB BD 0A 00 B9 FB 05 2E 8B 1E 04 00 FA 33 C0 8E C0 26 FF 36 0C 00 26 FF 36 0E 00 26 C7 06 0C 00 70 01 26 8C 0E 0E 00 BE 47 }
    condition:
        $a at pe.entry_point

}