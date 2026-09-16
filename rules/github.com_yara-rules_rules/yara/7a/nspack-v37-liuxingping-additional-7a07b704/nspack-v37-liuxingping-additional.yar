import "pe"
rule NsPacK_V37_LiuXingPing_additional: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }
    condition:
        $a at pe.entry_point

}