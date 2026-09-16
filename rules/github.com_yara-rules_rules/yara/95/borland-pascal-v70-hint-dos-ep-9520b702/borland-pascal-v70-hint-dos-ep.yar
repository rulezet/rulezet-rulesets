import "pe"
rule Borland_Pascal_v70_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B8 ?? ?? 8E D8 8C ?? ?? ?? 8C D3 8C C0 2B D8 8B C4 05 ?? ?? C1 ?? ?? 03 D8 B4 ?? CD 21 0E }
    condition:
        $a at pe.entry_point

}