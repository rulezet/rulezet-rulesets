import "pe"
rule LHA_SFX_Archive_v213L_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? FC BC ?? ?? 8C C8 05 ?? ?? 8E C0 E8 ?? ?? BB ?? ?? E8 ?? ?? 06 1F B4 30 CD 21 8B D8 1E }
    condition:
        $a at pe.entry_point

}