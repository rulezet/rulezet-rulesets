import "pe"
rule setupexe_Section14text: PEiD
{
    strings:
        $a = { 55 8B EC B8 7A 31 00 00 83 EC 08 53 56 57 A3 E8 5E 48 00 A3 EC 5E 48 }
    condition:
        $a at pe.entry_point

}