import "pe"
rule NsPack_V14_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }
    condition:
        $a at pe.entry_point

}