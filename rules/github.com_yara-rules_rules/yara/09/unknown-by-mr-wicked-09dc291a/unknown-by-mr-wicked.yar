import "pe"
rule unknown_by_Mr_Wicked: PEiD
{
    strings:
        $a = { BE 03 01 8B FE 8B CE 33 C0 8E D8 C7 06 0E 00 00 00 C6 06 04 00 0D 26 AC BA 00 00 52 FE 0E 04 00 74 0B E8 F7 FF D0 C8 FE C8 32 06 0E 00 C3 AA FF 0E 0E 00 75 DC 0E 1F BE 00 00 BF 00 01 2B CF 57 F3 A4 C3 }
    condition:
        $a at pe.entry_point

}