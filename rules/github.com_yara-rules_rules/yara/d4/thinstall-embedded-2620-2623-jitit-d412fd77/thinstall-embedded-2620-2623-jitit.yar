import "pe"
rule Thinstall_Embedded_2620_2623_Jitit: PEiD
{
    strings:
        $a = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }
    condition:
        $a at pe.entry_point

}