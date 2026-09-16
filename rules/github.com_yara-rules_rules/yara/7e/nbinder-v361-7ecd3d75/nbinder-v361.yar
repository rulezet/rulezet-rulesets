import "pe"
rule nBinder_v361: PEiD
{
    strings:
        $a = { 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C }
        $b = { 6E 73 70 61 63 6B 24 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}