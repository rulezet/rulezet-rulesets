import "pe"
rule TPack_05_m1: PEiD
{
    strings:
        $a = { 68 00 01 FD 60 BE 00 00 BF D3 FF B9 00 00 F3 A4 8B F7 BF 00 01 FC 46 E9 8E FE }
    condition:
        $a at pe.entry_point

}