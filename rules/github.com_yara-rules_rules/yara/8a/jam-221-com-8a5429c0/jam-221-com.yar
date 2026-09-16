import "pe"
rule Jam_221_COM: PEiD
{
    strings:
        $a = { 50 06 16 07 BE 06 02 8B FE B9 04 01 FD FA F3 2E A5 FB 06 BD 78 00 55 CB BE 00 00 8B FE BD 00 00 8D 9E 00 10 8D 97 00 00 B9 00 00 80 EF 10 8E DB 80 EE 10 8E C2 F3 A5 B5 80 3B DD 77 EE 33 C9 BE 00 00 8B FE 8E DA 8E C3 FC BA 01 00 EB 43 5D 2E }
    condition:
        $a at pe.entry_point

}