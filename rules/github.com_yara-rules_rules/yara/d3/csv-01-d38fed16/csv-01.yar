import "pe"
rule CSV_01: PEiD
{
    strings:
        $a = { FC BE 00 01 8B FE B9 00 00 51 56 57 B4 18 04 0A AC 90 90 2A C4 32 C4 AA E2 F6 5F 5E 59 03 F1 83 EE 03 A5 A4 B8 00 01 50 33 C0 33 DB 33 C9 33 D2 33 F6 33 FF C3 }
    condition:
        $a at pe.entry_point

}