import "pe"
rule hyings_PE_Armor_049_Hying: PEiD
{
    strings:
        $a = { 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}