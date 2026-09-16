import "pe"
rule OptLink_Pass_1: PEiD
{
    strings:
        $a = { 87 C0 55 56 57 52 51 53 50 9C FC 8C DA 83 C2 10 16 07 0E 1F 01 16 4E 01 01 16 52 01 33 F6 33 FF B9 AD 00 F3 A5 06 B8 30 00 50 BD 01 00 CB FD 8B 1E 54 01 B9 00 10 3B D9 77 02 8B CB 2B D9 8C D8 2B C1 8E D8 8C C0 2B C1 8E C0 03 C9 03 C9 03 C9 }
    condition:
        $a at pe.entry_point

}