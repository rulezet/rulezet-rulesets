import "pe"
rule Goats_Mutilator_v16_Goat_e0f_additional: PEiD
{
    strings:
        $a = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
    condition:
        $a at pe.entry_point

}