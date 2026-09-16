import "pe"
rule Visual_Cpp_31: PEiD
{
    strings:
        $a = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 00 00 40 00 68 00 00 40 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 00 00 00 00 33 D2 8B C8 8A D4 81 E1 FF 00 00 00 C1 E8 10 89 15 00 00 40 00 89 0D 00 00 40 00 A3 00 00 40 00 C1 E1 08 03 }
    condition:
        $a at pe.entry_point

}