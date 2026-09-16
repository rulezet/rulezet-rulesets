import "pe"
rule LCC_Win32_DLL: PEiD
{
    strings:
        $a = { 8B 44 24 08 56 83 E8 74 48 }
        $b = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}