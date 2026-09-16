import "pe"
rule NoodleCrypt_v20_additional: PEiD
{
    strings:
        $a = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }
    condition:
        $a at pe.entry_point

}