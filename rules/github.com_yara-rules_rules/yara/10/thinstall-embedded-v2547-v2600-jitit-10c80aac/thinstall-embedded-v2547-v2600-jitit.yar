import "pe"
rule Thinstall_Embedded_V2547_V2600_Jitit: PEiD
{
    strings:
        $a = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }
    condition:
        $a at pe.entry_point

}