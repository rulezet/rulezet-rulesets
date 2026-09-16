import "pe"
rule Safe_20_additional: PEiD
{
    strings:
        $a = { 83 EC 10 53 56 57 E8 C4 01 00 }
    condition:
        $a at pe.entry_point

}