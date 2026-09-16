import "pe"
rule RLPack_V118_Basic_Edition_aPLib_or_LZMA_ap0x_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? 02 00 00 33 FF E8 ?? 01 00 00 }
    condition:
        $a at pe.entry_point

}