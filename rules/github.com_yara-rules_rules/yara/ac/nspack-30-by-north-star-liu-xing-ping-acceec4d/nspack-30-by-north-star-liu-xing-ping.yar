import "pe"
rule NsPack_30_by_North_Star_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 55 F9 FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 7D F9 FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 11 F9 FF FF 89 95 }
    condition:
        $a at pe.entry_point

}