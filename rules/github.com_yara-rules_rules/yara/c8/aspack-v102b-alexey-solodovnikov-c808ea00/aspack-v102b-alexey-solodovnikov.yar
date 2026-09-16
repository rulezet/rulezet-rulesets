import "pe"
rule ASPack_v102b_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
    condition:
        $a at pe.entry_point

}