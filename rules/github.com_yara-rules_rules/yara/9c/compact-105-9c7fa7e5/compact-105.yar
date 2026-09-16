import "pe"
rule Compact_105: PEiD
{
    strings:
        $a = { 81 FC E8 80 77 04 B4 4C CD 21 FC BF 00 41 BE 00 01 B9 00 00 F3 A4 E9 00 40 BE 52 41 BF 00 01 AD 8B D6 8A D8 B7 00 03 F3 AC 3A C4 75 0D AC 3A C4 74 08 56 8B F2 8B CB F3 A4 5E AA 81 FF 00 00 72 E7 BF 52 41 88 0E 16 41 FE 0E 51 41 75 C0 E9 AF }
    condition:
        $a at pe.entry_point

}