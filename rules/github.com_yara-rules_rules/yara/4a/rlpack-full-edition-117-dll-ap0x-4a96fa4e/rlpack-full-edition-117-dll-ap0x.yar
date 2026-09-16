import "pe"
rule RLPack_Full_Edition_117_DLL_Ap0x: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }
    condition:
        $a at pe.entry_point

}