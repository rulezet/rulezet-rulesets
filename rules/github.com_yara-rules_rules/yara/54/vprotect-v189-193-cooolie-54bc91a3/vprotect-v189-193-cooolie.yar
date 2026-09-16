import "pe"
rule Vprotect_V189_193_CoooLie: PEiD
{
    strings:
        $a = { 58 89 03 8B 07 8B 5F 0C 8B 4F 04 8B 57 08 8B 6F 14 8B 77 18 FF 77 24 9D 8B 67 10 50 33 C0 F0 87 47 50 58 8B 7F 1C C3 }
    condition:
        $a at pe.entry_point

}