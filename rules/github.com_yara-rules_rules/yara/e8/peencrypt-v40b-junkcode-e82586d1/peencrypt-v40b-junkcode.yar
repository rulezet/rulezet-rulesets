import "pe"
rule PEEncrypt_v40b_JunkCode: PEiD
{
    strings:
        $a = { 66 ?? ?? 00 66 83 ?? 00 }
    condition:
        $a at pe.entry_point

}