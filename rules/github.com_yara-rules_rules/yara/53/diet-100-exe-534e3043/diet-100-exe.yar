import "pe"
rule Diet_100_EXE: PEiD
{
    strings:
        $a = { FC 06 1E 0E 8C C8 01 06 38 01 BA 00 00 03 C2 8B D8 05 00 00 8E DB 8E C0 33 F6 33 FF B9 08 00 F3 A5 4B 48 4A 79 EE 8E C3 8E D8 BE 4A 00 AD 8B E8 B2 10 EA 00 00 00 00 FF }
    condition:
        $a at pe.entry_point

}