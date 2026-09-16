import "pe"
rule Microsoft_Visual_Cpp_60_SFX_Custom: PEiD
{
    strings:
        $a = { E8 21 48 00 00 E9 16 FE FF FF 51 C7 01 08 B4 00 30 E8 A4 48 00 00 59 C3 56 8B F1 E8 EA FF FF FF F6 ?? ?? ?? ?? 74 07 56 E8 F6 04 00 00 59 8B C6 5E C2 04 00 8B 44 24 04 83 C1 09 51 83 C0 09 50 }
    condition:
        $a at pe.entry_point

}