import "pe"
rule PE_Armor_v07x_Hying: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 }
    condition:
        $a at pe.entry_point

}