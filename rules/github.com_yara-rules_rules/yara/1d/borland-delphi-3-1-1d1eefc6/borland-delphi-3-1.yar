import "pe"
rule Borland_Delphi_3_1: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F4 53 56 A1 0C CF 42 00 C6 00 01 B8 00 25 42 00 E8 00 00 FE FF BE 1C E1 42 00 A1 90 CE 42 00 E8 00 00 FE FF A1 CC CE 42 00 BA 00 00 42 00 E8 00 FD FE FF 84 C0 75 05 E8 00 02 FF FF E8 00 07 FF FF 33 C0 A3 14 E1 42 00 33 C0 A3 }
    condition:
        $a at pe.entry_point

}