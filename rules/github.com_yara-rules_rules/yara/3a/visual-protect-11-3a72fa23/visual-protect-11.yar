import "pe"
rule Visual_Protect_11: PEiD
{
    strings:
        $a = { 55 8B EC 51 53 56 57 83 25 6C 00 00 00 00 68 5C 00 00 00 FF 15 00 00 00 00 A3 BC 00 00 00 68 48 00 00 00 FF 35 BC 00 00 00 FF 15 04 00 00 00 A3 50 00 00 00 6A 00 FF 15 50 00 00 00 A3 A0 00 00 00 FF 35 A0 00 00 00 E8 42 04 00 00 59 89 45 FC }
    condition:
        $a at pe.entry_point

}