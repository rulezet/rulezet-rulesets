import "pe"
rule ComprEXE_10_COM: PEiD
{
    strings:
        $a = { FC 1E 06 8C DD 83 C5 10 89 E8 BA 00 00 8B 1E 02 00 29 D3 53 8E D8 8E C3 31 F6 31 FF B9 08 00 F3 A5 40 43 4A 75 EE B8 2B 00 50 CB 0E 1F BE 2A 01 B3 01 8E C5 31 FF 81 FF 00 80 72 0B 8C C0 05 00 08 8E C0 81 EF 00 80 E8 8A 00 74 08 B7 08 E8 9D }
    condition:
        $a at pe.entry_point

}