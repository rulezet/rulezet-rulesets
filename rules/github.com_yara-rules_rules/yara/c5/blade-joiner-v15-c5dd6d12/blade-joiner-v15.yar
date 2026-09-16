import "pe"
rule Blade_Joiner_v15: PEiD
{
    strings:
        $a = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }
    condition:
        $a at pe.entry_point

}