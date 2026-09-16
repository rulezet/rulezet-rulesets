import "pe"
rule _MSLRH_v032a_emadicius: PEiD
{
    strings:
        $a = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 }
    condition:
        $a at pe.entry_point

}