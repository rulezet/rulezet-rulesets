import "pe"
rule Themida_v2065_or_newer_c2009_Oreans_Technologies: PEiD
{
    strings:
        $a = { 52 BA 64 00 00 00 EB 1B B9 00 10 00 00 EB 05 03 C1 03 C3 49 0B C9 75 F7 52 54 54 FF 15 }
    condition:
        $a at pe.entry_point

}