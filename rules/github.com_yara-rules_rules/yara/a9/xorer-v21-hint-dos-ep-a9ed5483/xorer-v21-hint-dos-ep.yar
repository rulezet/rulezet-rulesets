import "pe"
rule Xorer_v21_Hint_DOS_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? BA ?? ?? B9 ?? ?? 51 B0 ?? E6 60 FA B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }
    condition:
        $a at pe.entry_point

}