import "pe"
rule GLBS_Install_Stub_32_bit_Wise: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC 2C 05 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 54 40 40 00 FF 15 50 40 40 00 8B F8 89 7D F4 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D F4 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D F4 EB EF 80 3F 22 75 04 47 89 7D F4 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D F4 53 FF 15 6C }
    condition:
        $a at pe.entry_point

}