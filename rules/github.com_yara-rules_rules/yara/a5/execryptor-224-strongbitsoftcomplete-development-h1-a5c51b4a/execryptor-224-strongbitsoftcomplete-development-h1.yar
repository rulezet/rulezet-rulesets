import "pe"
rule EXECryptor_224_StrongbitSoftComplete_Development_h1: PEiD
{
    strings:
        $a = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }
    condition:
        $a at pe.entry_point

}