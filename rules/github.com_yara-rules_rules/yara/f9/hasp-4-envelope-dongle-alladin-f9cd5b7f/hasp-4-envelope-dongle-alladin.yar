import "pe"
rule Hasp_4_envelope_dongle_Alladin: PEiD
{
    strings:
        $a = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 ?? ?? ?? ?? 5C 5C 2E 5C 46 45 6E 74 65 44 65 }
        $b = { 10 02 D0 51 0F 00 83 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}