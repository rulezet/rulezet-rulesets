import "pe"
rule VMProtect_07x_08_PolyTech_additional: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
    condition:
        $a at pe.entry_point

}