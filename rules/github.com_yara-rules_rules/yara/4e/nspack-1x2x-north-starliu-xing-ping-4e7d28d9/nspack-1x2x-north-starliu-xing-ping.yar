import "pe"
rule nSPack_1x2x_North_StarLiu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 }
    condition:
        $a at pe.entry_point

}