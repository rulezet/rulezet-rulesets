import "pe"
rule REC_v032_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 06 1E 52 B8 ?? ?? 1E CD 21 86 E0 3D }
    condition:
        $a at pe.entry_point

}