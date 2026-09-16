import "pe"
rule PEiD_Bundle_V102_DLL_BoB_BobSoft: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
    condition:
        $a at pe.entry_point

}