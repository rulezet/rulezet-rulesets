import "pe"
rule MESS_v120_Hint_DOS_EP_additional: PEiD
{
    strings:
        $a = { FA B9 ?? ?? F3 ?? AC ?? ?? EB ?? 1E 0E 1F BA ?? ?? 81 ?? ?? ?? B4 09 CD 21 1F B4 4C CD 21 }
    condition:
        $a at pe.entry_point

}