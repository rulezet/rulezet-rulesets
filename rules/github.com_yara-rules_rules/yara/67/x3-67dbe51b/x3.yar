import "pe"
rule X3: PEiD
{
    strings:
        $a = { 5E BF 00 01 57 B9 00 00 AC 34 00 AA E2 FA C3 }
    condition:
        $a at pe.entry_point

}