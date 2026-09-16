import "pe"
rule NsPack_3x_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D }
    condition:
        $a at pe.entry_point

}