import "pe"
rule Protect_3031_COM: PEiD
{
    strings:
        $a = { 50 1E 06 0E 55 0E 1F 33 C0 8E C0 FA FC 26 A1 04 00 50 26 A1 06 00 50 26 A1 0C 00 50 26 A1 0E 00 50 8C C8 26 A3 06 00 26 C7 06 04 00 00 00 26 A3 0E 00 26 C7 06 0C 00 00 00 FB CD 01 }
    condition:
        $a at pe.entry_point

}