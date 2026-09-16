import "pe"
rule Protect_40_COM: PEiD
{
    strings:
        $a = { E8 00 00 5D 81 ED 13 01 33 C0 8E D8 8B F0 BF 70 00 B9 08 00 FC F3 A5 FD 87 FE 8C C0 8E D8 33 C0 8E C0 4F 4F 8B C2 AB B8 AE 02 03 C5 AB 8B C2 AB B8 BB 01 03 C5 AB 8B C2 AB E4 21 A2 6B 00 B8 EF 01 03 C5 AB 8B C2 AB B8 F8 01 03 C5 AB 1E 07 B0 }
    condition:
        $a at pe.entry_point

}