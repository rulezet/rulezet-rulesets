import "pe"
rule MESS_v120_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6 }
    condition:
        $a at pe.entry_point

}