import "pe"
rule UC_2_EXE_24: PEiD
{
    strings:
        $a = { 50 1E 0E 1F FC 33 F6 E8 00 01 16 07 33 F6 33 FF B9 00 01 F3 A5 06 B8 5D 00 50 CB 03 ED FE CE 75 05 AD 8B E8 B6 10 13 DB C3 03 ED FE CE 75 05 AD 8B E8 B6 10 73 05 43 3A DA 75 EE C3 8A 97 39 30 BB 01 00 0A D2 74 07 E8 D1 FF FE CA 75 F9 8B C3 }
    condition:
        $a at pe.entry_point

}