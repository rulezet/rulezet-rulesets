import "pe"
rule nSpack_V13_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }
    condition:
        $a at pe.entry_point

}