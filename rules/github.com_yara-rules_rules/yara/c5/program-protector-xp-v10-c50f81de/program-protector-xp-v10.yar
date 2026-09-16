import "pe"
rule Program_Protector_XP_v10: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }
    condition:
        $a at pe.entry_point

}