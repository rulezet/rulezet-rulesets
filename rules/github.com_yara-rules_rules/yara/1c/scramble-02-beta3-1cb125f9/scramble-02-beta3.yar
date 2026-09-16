import "pe"
rule SCRAMBLE_02_beta3: PEiD
{
    strings:
        $a = { 60 9C FC 00 00 01 00 00 01 BA 13 00 01 55 01 2A D2 FF E7 B9 00 00 57 51 F3 A4 59 5E 03 F1 05 00 B4 00 00 31 04 E2 FA 9D 61 68 00 01 C3 }
    condition:
        $a at pe.entry_point

}