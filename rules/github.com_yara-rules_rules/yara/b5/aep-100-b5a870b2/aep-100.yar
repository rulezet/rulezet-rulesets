import "pe"
rule AEP_100: PEiD
{
    strings:
        $a = { E4 21 2E A3 64 00 33 C0 8B D8 5D B9 00 01 50 B8 FF 03 E6 21 0F A9 E6 A1 53 8B DF E4 21 23 D8 4B 0F A1 4B 66 65 FF 37 83 EB 04 49 75 F6 2E C6 06 9C 00 CB 68 17 00 C3 F4 02 41 05 FF 3E E7 5F 32 25 8A 2D 8C C8 F5 FC 8C C0 C0 FE 8C D0 C2 FE FE }
    condition:
        $a at pe.entry_point

}