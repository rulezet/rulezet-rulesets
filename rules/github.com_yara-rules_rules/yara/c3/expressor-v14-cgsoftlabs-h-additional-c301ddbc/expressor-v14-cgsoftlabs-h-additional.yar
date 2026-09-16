import "pe"
rule eXPressor_v14_CGSoftLabs_h_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }
    condition:
        $a at pe.entry_point

}