import "pe"
rule Diet_144_145_COM: PEiD
{
    strings:
        $a = { F9 9C EB 0A 00 00 0C 00 00 00 9D 89 F8 9C 55 06 1E 57 56 52 51 53 50 E8 00 00 59 B1 04 D3 E9 8C C8 03 C1 8E D8 8E C0 BE 00 00 BF 00 00 B9 00 00 FD F3 A5 FC 8B F7 33 FF AD AD 8B E8 B2 10 E9 00 00 64 6C 7A }
    condition:
        $a at pe.entry_point

}