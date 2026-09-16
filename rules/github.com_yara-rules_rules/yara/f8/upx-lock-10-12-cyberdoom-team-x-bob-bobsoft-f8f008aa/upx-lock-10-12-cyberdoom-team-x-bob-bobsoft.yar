import "pe"
rule Upx_Lock_10_12_CyberDoom_Team_X_BoB_BobSoft: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
    condition:
        $a at pe.entry_point

}