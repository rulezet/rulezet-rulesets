import "pe"
rule RLPack_Full_Edition_117_DLL_LZMA: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 ?? ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 EB 09 00 00 89 85 }
    condition:
        $a at pe.entry_point

}