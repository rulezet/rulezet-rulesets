import "pe"
rule LHA_SFX_Archive_v205S_v254S_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? FC BC ?? ?? 8C C8 05 ?? ?? 8E C0 EB }
    condition:
        $a at pe.entry_point

}