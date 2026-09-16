import "pe"
rule Microsoft_QBasic_v40_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 0E 1F B8 ?? ?? 50 9A ?? ?? ?? ?? 8E DA 93 8A 17 0A D2 74 ?? B4 ?? CD 21 43 }
    condition:
        $a at pe.entry_point

}