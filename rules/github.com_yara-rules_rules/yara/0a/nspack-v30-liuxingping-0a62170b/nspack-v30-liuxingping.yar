import "pe"
rule NsPacK_V30_LiuXingPing: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 }
    condition:
        $a at pe.entry_point

}