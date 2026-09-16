import "pe"
rule nSpack_V2x_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }
        $b = { 6E 73 70 61 63 6B 24 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}