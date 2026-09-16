import "pe"
rule Username_300_COM: PEiD
{
    strings:
        $a = { E8 00 00 5D 83 ED 03 FA FC 33 F6 8E DE BF 99 01 03 FD B9 14 00 F3 A4 8B FC 8B 1E 84 00 A1 86 00 89 1E 0C 00 A3 0E 00 8B 16 40 00 8B 1E 42 00 B8 AD FD 8E D0 B8 38 25 8B E0 53 52 8C C8 8B E7 8E D0 FB 0E 1F BE 51 00 B9 24 01 3E 31 0A 46 46 E2 }
    condition:
        $a at pe.entry_point

}