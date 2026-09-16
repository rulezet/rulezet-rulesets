import "pe"
rule NoodleCrypt_v20: PEiD
{
    strings:
        $a = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
        $b = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}