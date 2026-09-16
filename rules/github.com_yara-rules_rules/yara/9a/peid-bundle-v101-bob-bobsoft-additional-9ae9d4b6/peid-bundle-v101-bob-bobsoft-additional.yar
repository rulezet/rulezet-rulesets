import "pe"
rule PEiD_Bundle_v101_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
    condition:
        $a at pe.entry_point

}