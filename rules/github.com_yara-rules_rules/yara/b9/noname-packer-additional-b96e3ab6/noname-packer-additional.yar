import "pe"
rule NoName_Packer_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 2E 34 46 00 B9 55 4A 46 00 81 E9 26 37 46 00 89 EA 81 C2 26 37 46 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }
    condition:
        $a at pe.entry_point

}