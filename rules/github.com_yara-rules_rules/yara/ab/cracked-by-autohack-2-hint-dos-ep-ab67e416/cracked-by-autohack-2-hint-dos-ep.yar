import "pe"
rule Cracked_by_Autohack_2_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 0E 1F B4 09 BA ?? ?? CD 21 FA 8E 06 ?? ?? BE ?? ?? 8B 0E ?? ?? 83 F9 }
    condition:
        $a at pe.entry_point

}