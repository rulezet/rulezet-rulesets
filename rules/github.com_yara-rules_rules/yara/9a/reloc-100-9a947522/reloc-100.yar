import "pe"
rule RELOC_100: PEiD
{
    strings:
        $a = { 1E 06 8C C8 2E 2B 06 6E 00 8E C0 8B D0 2E 8C 06 6E 00 2E 8B 36 70 00 2E 8B 0E 72 00 E3 1E BD 74 00 2E 8B 36 70 00 2E 03 76 00 2E A1 6E 00 2E 03 46 02 8E C0 83 C5 04 26 01 14 E2 E5 07 1F FA 2E 8B 26 6C 00 8C C8 2E 2B 06 6A 00 8E D0 8C C8 2E }
    condition:
        $a at pe.entry_point

}