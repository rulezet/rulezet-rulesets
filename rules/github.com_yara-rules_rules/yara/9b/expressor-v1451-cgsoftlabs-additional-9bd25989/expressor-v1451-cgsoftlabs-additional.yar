import "pe"
rule eXPressor_V1451_CGSoftLabs_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C }
    condition:
        $a at pe.entry_point

}