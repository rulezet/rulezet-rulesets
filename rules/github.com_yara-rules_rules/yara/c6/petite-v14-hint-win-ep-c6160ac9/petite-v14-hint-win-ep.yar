import "pe"
rule Petite_v14_Hint_WIN_EP: PEiD
{
    strings:
        $a = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }
    condition:
        $a at pe.entry_point

}