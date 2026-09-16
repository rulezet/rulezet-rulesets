import "pe"
rule Armadillo_v430_440_Silicon_Realms_Toolworks_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24 ?? ?? 00 33 F6 56 E8 78 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 43 13 00 00 FF 15 8C ?? ?? 00 A3 24 }
    condition:
        $a at pe.entry_point

}