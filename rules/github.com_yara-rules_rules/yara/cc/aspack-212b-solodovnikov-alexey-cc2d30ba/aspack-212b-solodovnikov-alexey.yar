import "pe"
rule ASPack_212b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { ?? 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB EC FF FF FF 03 DD 81 EB 00 ?? ?? 00 83 BD 22 04 00 00 00 89 9D 22 04 00 00 0F 85 65 03 00 00 8D 85 2E 04 00 00 50 FF 95 4C 0F 00 00 89 85 26 04 00 00 8B F8 8D 5D 5E 53 50 FF 95 48 0F 00 00 89 85 4C 05 00 00 8D 5D 6B 53 57 FF 95 48 0F }
    condition:
        $a at pe.entry_point

}