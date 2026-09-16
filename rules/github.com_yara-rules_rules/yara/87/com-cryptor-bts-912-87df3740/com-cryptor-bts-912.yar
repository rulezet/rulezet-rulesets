import "pe"
rule Com_Cryptor_BTS_912: PEiD
{
    strings:
        $a = { B7 00 E8 05 00 83 ED 02 EB 03 5D 55 C3 BF 1A 00 03 FD 8B F7 B9 71 02 AC 02 C7 AA E2 FA }
    condition:
        $a at pe.entry_point

}