import "pe"
rule Turbo_Prolog_1986: PEiD
{
    strings:
        $a = { FA B8 00 00 8E D8 B8 00 00 A3 00 00 8E D0 BC 00 01 FB 8C 06 00 00 26 8E 06 2C 00 8C 06 00 00 B8 00 00 A3 00 00 9A 00 00 00 00 89 1E 00 00 A3 00 00 9A 00 00 00 00 00 00 9A 00 00 00 00 83 C4 04 00 00 00 00 00 00 00 00 00 00 00 00 9A 00 00 00 }
    condition:
        $a at pe.entry_point

}