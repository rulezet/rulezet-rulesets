import "pe"
rule RPolyCryptor_V142_Vaska_SignByfly: PEiD
{
    strings:
        $a = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 }
    condition:
        $a at pe.entry_point

}