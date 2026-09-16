import "pe"
rule unknown_by_GyikSoft_2: PEiD
{
    strings:
        $a = { 8C C8 05 00 00 50 B8 00 00 50 B0 FF 06 8C D2 06 83 EA 1E 50 B0 08 52 FC 50 8C D2 8C CD BB 00 00 03 EB 4A 8E DD 8E C2 4D B9 08 00 33 FF BE 00 00 AD 35 00 00 AB E2 F9 4B 79 E8 8E DA 0E BE 00 00 33 DB 8B FB 07 CB }
    condition:
        $a at pe.entry_point

}