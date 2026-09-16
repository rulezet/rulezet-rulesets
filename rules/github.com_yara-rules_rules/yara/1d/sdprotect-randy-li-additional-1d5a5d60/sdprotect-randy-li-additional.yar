import "pe"
rule SDProtect_Randy_Li_additional: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }
    condition:
        $a at pe.entry_point

}