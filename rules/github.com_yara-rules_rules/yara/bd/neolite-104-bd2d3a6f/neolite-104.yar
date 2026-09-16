import "pe"
rule NeoLite_104: PEiD
{
    strings:
        $a = { 8B 44 24 04 8D 54 24 FC 23 05 11 10 00 00 E8 EB 04 00 00 FF 35 F4 13 00 00 50 FF 25 FC 13 00 00 94 9A 8D 91 9A 93 CC CD 00 B8 93 90 9D 9E 93 BE 93 93 90 9C 00 B8 93 90 9D 9E 93 B9 8D 9A 9A 00 B8 9A 8B B2 90 9B 8A 93 9A B7 9E 91 9B 93 9A BE }
    condition:
        $a at pe.entry_point

}