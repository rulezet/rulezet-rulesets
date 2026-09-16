import "pe"
rule PEncrypt_v31_JunkCode: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? 00 F0 0F C6 }
    condition:
        $a at pe.entry_point

}