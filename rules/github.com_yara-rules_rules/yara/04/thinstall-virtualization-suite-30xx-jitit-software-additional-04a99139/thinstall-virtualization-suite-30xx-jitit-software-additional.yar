import "pe"
rule Thinstall_Virtualization_Suite_30xx_Jitit_Software_additional: PEiD
{
    strings:
        $a = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 00 00 00 01 68 00 ?? 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 }
    condition:
        $a at pe.entry_point

}