import "pe"
rule LCC_Win32_v1x: PEiD
{
    strings:
        $a = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 FF 75 10 FF 75 0C FF 75 08 }
        $b = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}