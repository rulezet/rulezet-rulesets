import "pe"
rule DCrypt_Private_09b_drmist: PEiD
{
    strings:
        $a = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }
    condition:
        $a at pe.entry_point

}