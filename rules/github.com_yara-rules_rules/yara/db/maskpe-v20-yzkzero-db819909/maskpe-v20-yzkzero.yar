import "pe"
rule MaskPE_V20_yzkzero: PEiD
{
    strings:
        $a = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }
    condition:
        $a at pe.entry_point

}