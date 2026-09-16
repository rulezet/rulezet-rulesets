import "pe"
rule NFO_10: PEiD
{
    strings:
        $a = { 60 9C 8D 50 12 2B C9 B1 1E 8A 02 34 00 88 02 42 E2 F7 }
    condition:
        $a at pe.entry_point

}