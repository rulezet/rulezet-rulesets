import "pe"
rule Microsoft_CAB_SFX_module_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }
    condition:
        $a at pe.entry_point

}