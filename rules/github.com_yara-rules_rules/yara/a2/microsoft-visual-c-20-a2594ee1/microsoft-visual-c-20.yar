import "pe"
rule Microsoft_Visual_C_20: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 }
    condition:
        $a at pe.entry_point

}