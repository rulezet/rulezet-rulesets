import "pe"
rule DIET_v144_v145f_Hint_DOS_EP_p_11: PEiD
{
    strings:
        $a = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52 }
    condition:
        $a at pe.entry_point

}