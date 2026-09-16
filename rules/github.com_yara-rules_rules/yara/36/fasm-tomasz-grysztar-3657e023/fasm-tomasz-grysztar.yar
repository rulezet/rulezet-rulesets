import "pe"
rule fasm_Tomasz_Grysztar: PEiD
{
    strings:
        $a = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }
        $b = { 6A 24 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}