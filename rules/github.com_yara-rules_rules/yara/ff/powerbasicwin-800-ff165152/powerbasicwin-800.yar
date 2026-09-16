import "pe"
rule PowerBASICWin_800_: PEiD
{
    strings:
        $a = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 14 04 00 00 E9 19 02 }
    condition:
        $a at pe.entry_point

}