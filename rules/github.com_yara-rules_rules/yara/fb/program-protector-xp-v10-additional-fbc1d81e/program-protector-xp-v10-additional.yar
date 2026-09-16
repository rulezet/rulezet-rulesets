import "pe"
rule Program_Protector_XP_v10_additional: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}