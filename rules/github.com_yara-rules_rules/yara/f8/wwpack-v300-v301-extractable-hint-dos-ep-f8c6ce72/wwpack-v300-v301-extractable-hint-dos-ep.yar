import "pe"
rule WWPACK_v300_v301_Extractable_Hint_DOS_EP: PEiD
{
    strings:
        $a = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }
    condition:
        $a at pe.entry_point

}