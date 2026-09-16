import "pe"
rule NeoLite_200: PEiD
{
    strings:
        $a = { 8B 44 24 04 23 05 00 00 00 00 E8 ED 04 00 00 FE 05 00 00 00 00 FF E0 80 3D 00 00 00 00 00 75 13 90 90 90 90 50 2B C0 E8 D0 04 00 00 58 FE 05 00 00 00 00 C3 94 9A 8D 91 9A 93 CC CD 00 B8 93 90 9D 9E 93 BE 93 93 90 9C 00 B8 93 90 9D 9E 93 B9 }
    condition:
        $a at pe.entry_point

}