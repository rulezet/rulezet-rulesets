import "pe"
rule _MSLRH_v01_emadicius: PEiD
{
    strings:
        $a = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 }
    condition:
        $a at pe.entry_point

}