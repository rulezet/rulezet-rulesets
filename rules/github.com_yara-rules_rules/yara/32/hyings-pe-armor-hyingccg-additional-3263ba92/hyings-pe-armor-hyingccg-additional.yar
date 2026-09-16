import "pe"
rule hyings_PE_Armor_hyingCCG_additional: PEiD
{
    strings:
        $a = { E8 AA 00 00 00 2D ?? ?? ?? 00 00 00 00 00 00 00 00 3D }
    condition:
        $a at pe.entry_point

}