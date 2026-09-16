import "pe"
rule CRYPTCOM_by_unknown: PEiD
{
    strings:
        $a = { BE 00 01 56 B9 00 00 C7 04 00 00 C6 44 02 00 81 34 00 93 46 46 E2 F8 31 F6 31 C9 C3 00 }
    condition:
        $a at pe.entry_point

}