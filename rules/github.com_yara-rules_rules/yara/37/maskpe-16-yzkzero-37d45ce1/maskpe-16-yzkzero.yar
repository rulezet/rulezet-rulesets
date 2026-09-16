import "pe"
rule MaskPE_16_yzkzero: PEiD
{
    strings:
        $a = { 36 81 2C 24 ?? ?? ?? 00 C3 60 }
    condition:
        $a at pe.entry_point

}