import "pe"
rule Nullsoft_Install_System_v1xx_Nullsoft: PEiD
{
    strings:
        $a = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 80 40 00 68 00 04 00 00 FF 15 ?? 81 40 00 50 56 FF 15 ?? 81 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D F4 81 40 00 84 C0 74 19 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 }
    condition:
        $a at pe.entry_point

}