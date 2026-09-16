import "pe"
rule AppLok_95_20: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F4 E8 2D 36 FD FF E8 EC 4B FD FF E8 27 7B FD FF E8 EA E4 FD FF E8 21 E6 FD FF E8 6C 05 FE FF E8 73 7C FE FF E8 4E 49 FF FF E8 DD 81 FF FF E8 AC AB FF FF A1 24 16 43 00 E8 92 3F FF FF BA 34 FE 42 00 A1 24 16 43 00 E8 AF 3C FF }
    condition:
        $a at pe.entry_point

}