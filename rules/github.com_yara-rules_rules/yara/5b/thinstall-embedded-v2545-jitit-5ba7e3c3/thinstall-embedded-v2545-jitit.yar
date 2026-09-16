import "pe"
rule Thinstall_Embedded_V2545_Jitit: PEiD
{
    strings:
        $a = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}