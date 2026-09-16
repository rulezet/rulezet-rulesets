import "pe"
rule dePACK_deNULL: PEiD
{
    strings:
        $a = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? 00 00 E8 ?? 00 00 00 }
        $b = { EB 01 DD 60 68 00 ?? ?? ?? 68 ?? ?? ?? 00 E8 ?? 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}