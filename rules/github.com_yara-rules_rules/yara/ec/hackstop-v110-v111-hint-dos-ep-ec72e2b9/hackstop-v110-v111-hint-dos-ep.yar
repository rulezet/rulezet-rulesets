import "pe"
rule HACKSTOP_v110_v111_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 ?? ?? 58 EB }
    condition:
        $a at pe.entry_point

}