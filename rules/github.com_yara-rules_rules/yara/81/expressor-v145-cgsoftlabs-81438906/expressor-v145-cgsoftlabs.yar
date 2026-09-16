import "pe"
rule eXpressor_v145_CGSoftLabs: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }
    condition:
        $a at pe.entry_point

}