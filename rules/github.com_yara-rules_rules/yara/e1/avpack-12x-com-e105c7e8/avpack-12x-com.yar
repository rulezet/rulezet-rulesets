import "pe"
rule AVPack_12x_COM: PEiD
{
    strings:
        $a = { EB 12 41 56 50 41 43 4B 16 01 01 00 00 00 00 00 00 00 00 00 8C DA 03 16 12 01 39 16 02 00 73 18 B4 09 BA 28 01 CD 21 C3 4F 75 74 20 6F 66 20 6D 65 6D 6F 72 79 0D 0A 24 8B DC 83 EA 40 FA 8E D2 BC 00 04 FB 50 1E 53 8E C2 B9 00 01 8B F1 33 FF }
    condition:
        $a at pe.entry_point

}