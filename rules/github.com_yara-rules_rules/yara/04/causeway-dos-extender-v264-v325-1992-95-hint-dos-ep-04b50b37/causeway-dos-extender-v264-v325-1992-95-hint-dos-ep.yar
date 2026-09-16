import "pe"
rule CauseWay_DOS_Extender_v264_v325_1992_95_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? 8B E8 8C C6 0E 1F 8C C0 05 ?? ?? 01 ?? ?? ?? B8 ?? ?? CD 21 3C ?? 73 }
    condition:
        $a at pe.entry_point

}