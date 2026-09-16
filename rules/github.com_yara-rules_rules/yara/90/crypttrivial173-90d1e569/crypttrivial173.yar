import "pe"
rule CryptTrivial173: PEiD
{
    strings:
        $a = { EB 18 90 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 BB 00 FE 00 1F 4B EB FB D1 81 0F D1 0D D8 9B 0B E8 32 55 D0 4A D2 45 D7 5E 5D 4F 8F CE B4 09 57 1B 94 C4 C3 81 C1 C1 78 FC BD BF D8 01 9B B3 38 B1 94 60 28 E8 41 }
    condition:
        $a at pe.entry_point

}