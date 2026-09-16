import "pe"
rule Borland_Cpp_Win32_1995: PEiD
{
    strings:
        $a = { A1 5A 00 00 00 C1 E0 02 A3 5E 00 00 00 57 51 33 C0 BF 00 00 00 00 B9 00 00 00 00 3B CF 76 05 2B CF FC F3 AA 59 5F 64 67 8B 16 04 00 89 15 6E 00 00 00 8B 42 F8 A3 66 00 00 00 8B 42 FC A3 6A 00 00 00 83 EA 04 89 15 00 00 00 00 83 EA 04 3B D4 }
    condition:
        $a at pe.entry_point

}