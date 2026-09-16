import "pe"
rule KByS_V028_shoooo_Sign_by_fly: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 }
    condition:
        $a at pe.entry_point

}