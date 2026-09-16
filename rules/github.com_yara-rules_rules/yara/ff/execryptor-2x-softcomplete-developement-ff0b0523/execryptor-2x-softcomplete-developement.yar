import "pe"
rule EXECryptor_2x_SoftComplete_Developement: PEiD
{
    strings:
        $a = { A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF }
    condition:
        $a at pe.entry_point

}