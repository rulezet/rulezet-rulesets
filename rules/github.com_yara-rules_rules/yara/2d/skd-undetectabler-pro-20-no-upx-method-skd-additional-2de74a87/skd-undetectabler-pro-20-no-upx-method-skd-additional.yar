import "pe"
rule SkD_Undetectabler_Pro_20_No_UPX_Method_SkD_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD }
    condition:
        $a at pe.entry_point

}