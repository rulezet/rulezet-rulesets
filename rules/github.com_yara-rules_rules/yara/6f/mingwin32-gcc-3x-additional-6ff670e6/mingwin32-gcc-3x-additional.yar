import "pe"
rule MingWin32_GCC_3x_additional: PEiD
{
    strings:
        $a = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55 }
    condition:
        $a at pe.entry_point

}