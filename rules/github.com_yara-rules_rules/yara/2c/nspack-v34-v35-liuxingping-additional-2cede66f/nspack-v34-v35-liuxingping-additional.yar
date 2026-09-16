import "pe"
rule NsPacK_V34_V35_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84 }
    condition:
        $a at pe.entry_point

}