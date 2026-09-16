import "pe"
rule Microsoft_Visual_C_v70_Basic_NET: PEiD
{
    strings:
        $a = { 53 55 56 8B 74 24 14 85 F6 57 B8 }
        $b = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}