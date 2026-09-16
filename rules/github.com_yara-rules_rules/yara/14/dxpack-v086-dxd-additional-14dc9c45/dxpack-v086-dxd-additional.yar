import "pe"
rule DxPack_V086_Dxd_additional: PEiD
{
    strings:
        $a = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
    condition:
        $a at pe.entry_point

}