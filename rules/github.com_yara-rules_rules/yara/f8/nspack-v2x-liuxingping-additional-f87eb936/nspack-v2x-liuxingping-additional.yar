import "pe"
rule nSpack_V2x_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }
    condition:
        $a at pe.entry_point

}