import "pe"
rule LHARC_SFX_Archive_v1131c_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? ?? ?? ?? ?? 24 4C 48 61 72 ?? 27 73 ?? 53 46 58 }
    condition:
        $a at pe.entry_point

}