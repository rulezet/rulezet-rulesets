import "pe"
rule PeX_099: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D5 22 40 00 E8 06 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 E8 01 00 00 00 9A 59 8D 95 27 23 40 00 E8 01 00 00 00 69 58 66 BF 4D 4A E8 C1 01 00 00 8D 52 F9 E8 01 00 00 00 }
    condition:
        $a at pe.entry_point

}