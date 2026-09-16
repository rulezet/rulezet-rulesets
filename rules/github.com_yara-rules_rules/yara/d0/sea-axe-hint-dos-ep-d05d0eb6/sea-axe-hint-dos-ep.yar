import "pe"
rule SEA_AXE_Hint_DOS_EP: PEiD
{
    strings:
        $a = { FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3 }
    condition:
        $a at pe.entry_point

}