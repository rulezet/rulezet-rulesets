import "pe"
rule Maked_by_The_DRAW_v_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? B4 ?? CD 10 BB ?? ?? 3C ?? 74 ?? 3C ?? 74 ?? C6 }
    condition:
        $a at pe.entry_point

}