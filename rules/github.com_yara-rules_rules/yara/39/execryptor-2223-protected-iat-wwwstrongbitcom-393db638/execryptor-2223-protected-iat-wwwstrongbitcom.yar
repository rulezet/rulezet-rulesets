import "pe"
rule EXECryptor_2223_protected_IAT_wwwstrongbitcom: PEiD
{
    strings:
        $a = { CC ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? B4 ?? ?? ?? 08 ?? ?? ?? 00 00 00 00 FF FF FF FF E8 ?? ?? ?? 04 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 }
    condition:
        $a at pe.entry_point

}