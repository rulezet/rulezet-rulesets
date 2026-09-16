import "pe"
rule Upx_Lock_v10_CyberDoom_Team_X: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
    condition:
        $a at pe.entry_point

}