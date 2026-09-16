import "pe"
rule Alloy_v1x2000_Prakash_Gautam: PEiD
{
    strings:
        $a = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD 6A 04 68 00 10 ?? ?? 68 00 02 ?? ?? 6A 00 FF 95 46 23 40 ?? 0B }
    condition:
        $a at pe.entry_point

}