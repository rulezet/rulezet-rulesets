import "pe"
rule TPAV_Cryptor_V11_msaha_dev_SignByfly: PEiD
{
    strings:
        $a = { 8D 85 08 FF FF FF 50 8D 85 C4 FE FF FF 50 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 8D 95 C0 FE FF FF 33 C0 E8 ?? ?? FF FF 8B 85 C0 FE FF FF E8 ?? ?? FF FF 50 6A 00 FF 15 2C ?? ?? 70 }
    condition:
        $a at pe.entry_point

}