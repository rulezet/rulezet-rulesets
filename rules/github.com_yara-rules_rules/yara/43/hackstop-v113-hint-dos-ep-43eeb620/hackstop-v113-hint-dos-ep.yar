import "pe"
rule HACKSTOP_v113_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA }
    condition:
        $a at pe.entry_point

}