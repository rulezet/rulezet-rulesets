import "pe"
rule NSPack_3x_Liu_Xing_Ping: PEiD
{
    strings:
        $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }
    condition:
        $a at pe.entry_point

}