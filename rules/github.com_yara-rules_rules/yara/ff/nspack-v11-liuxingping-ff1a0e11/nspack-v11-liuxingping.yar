import "pe"
rule NsPack_V11_LiuXingPing_: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
    condition:
        $a at pe.entry_point

}