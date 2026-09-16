import "pe"
rule RLPack_V115_V117_Dll_ap0x_Sign_by_fly: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }
    condition:
        $a at pe.entry_point

}