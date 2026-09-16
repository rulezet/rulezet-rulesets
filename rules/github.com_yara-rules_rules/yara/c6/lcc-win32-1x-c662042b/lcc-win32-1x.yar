import "pe"
rule LCC_Win32_1x: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? 00 68 9A 10 40 00 50 }
    condition:
        $a at pe.entry_point

}