import "pe"
rule NsPacK_V31_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 }
    condition:
        $a at pe.entry_point

}