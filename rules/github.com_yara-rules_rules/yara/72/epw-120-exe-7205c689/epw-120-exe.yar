import "pe"
rule EPW_120_EXE: PEiD
{
    strings:
        $a = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 05 10 00 2E A3 0A 00 8E D8 A1 08 00 2E 03 06 0A 00 2E A3 0C 00 A1 0E 00 2E 03 06 0A 00 2E A3 06 00 A1 10 00 2E A3 04 00 A1 14 00 2E A3 00 00 A1 16 00 2E 03 06 0A 00 2E A3 02 00 0E 1F BA 32 00 }
    condition:
        $a at pe.entry_point

}