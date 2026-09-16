import "pe"
rule Cracked_by_AutoHack_1_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FA 50 51 57 56 1E 06 2E 80 3E ?? ?? ?? 74 ?? 8E 06 ?? ?? 2B FF FC }
    condition:
        $a at pe.entry_point

}