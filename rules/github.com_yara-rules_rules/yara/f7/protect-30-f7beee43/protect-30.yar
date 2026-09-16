import "pe"
rule Protect_30: PEiD
{
    strings:
        $a = { 2E A3 00 00 8C D8 2E A3 02 00 8C C8 2E A3 06 00 2E 89 2E 04 00 33 C0 8E C0 FA FC 26 A1 04 00 2E A3 0A 00 26 A1 06 00 2E A3 08 00 26 A1 0C 00 2E A3 0E 00 26 A1 0E 00 2E A3 0C 00 2E A1 06 00 26 A3 06 00 26 C7 06 04 00 D4 01 26 A3 0E 00 26 C7 }
    condition:
        $a at pe.entry_point

}