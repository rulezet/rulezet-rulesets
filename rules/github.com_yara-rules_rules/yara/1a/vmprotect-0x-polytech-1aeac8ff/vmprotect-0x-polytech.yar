import "pe"
rule VMProtect_0x_PolyTech: PEiD
{
    strings:
        $a = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 }
    condition:
        $a at pe.entry_point

}