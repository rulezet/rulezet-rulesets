import "pe"
rule ASPack_v212: PEiD
{
    strings:
        $a = { 60 E8 03 ?? ?? ?? E9 EB 04 5D 45 55 C3 E8 }
        $b = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}