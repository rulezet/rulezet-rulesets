import "pe"
rule XPack_136_EXE: PEiD
{
    strings:
        $a = { 2E C7 06 01 01 00 00 8B EC EB 01 E8 2E C6 06 08 05 FA EB 00 9A BC 15 05 2E C6 06 14 05 C3 EB 00 9A 3B 05 06 09 95 19 99 26 03 62 F1 03 6D 05 88 05 13 06 49 06 E2 00 5D 06 CF 00 45 06 AC 00 48 06 AA 00 3C 06 FC 00 33 E4 8E D4 83 C4 10 2E 8F }
    condition:
        $a at pe.entry_point

}