import "pe"
rule eXpressor_v145_CGSoftLabs_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }
    condition:
        $a at pe.entry_point

}