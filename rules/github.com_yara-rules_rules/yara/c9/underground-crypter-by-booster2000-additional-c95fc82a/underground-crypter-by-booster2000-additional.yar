import "pe"
rule UnderGround_Crypter_by_Booster2000_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }
    condition:
        $a at pe.entry_point

}