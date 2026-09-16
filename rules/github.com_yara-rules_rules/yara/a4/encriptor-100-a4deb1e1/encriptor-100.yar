import "pe"
rule Encriptor_100: PEiD
{
    strings:
        $a = { B9 60 EA BE 87 01 BF 87 01 AC D0 C8 AA E2 FA BE 6E 01 BF 48 EE AC AA 81 FE 87 01 75 F8 8C C8 BF 48 EE FF E7 BE 88 01 BF 00 01 B9 60 EA F3 A4 B8 00 00 BB 00 00 B9 00 00 BF 00 01 FF E7 24 }
    condition:
        $a at pe.entry_point

}