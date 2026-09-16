import "pe"
rule eXPressor_v120b_additional: PEiD
{
    strings:
        $a = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 ?? ?? ?? 00 2B 05 84 ?? ?? 00 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 00 74 16 A1 ?? ?? ?? 00 03 05 80 ?? ?? 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 ?? ?? ?? 00 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 ?? ?? ?? 00 8D 84 05 EF FE FF FF 89 85 38 FE FF FF 8B 85 38 FE FF FF 0F BE 00 83 F8 5C }
    condition:
        $a at pe.entry_point

}