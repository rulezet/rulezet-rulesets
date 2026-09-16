import "pe"
rule KByS_Packer_v028: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? 00 E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 }
    condition:
        $a at pe.entry_point

}