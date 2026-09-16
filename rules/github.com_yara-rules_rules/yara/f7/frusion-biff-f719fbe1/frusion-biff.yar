import "pe"
rule Frusion_biff: PEiD
{
    strings:
        $a = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }
    condition:
        $a at pe.entry_point

}