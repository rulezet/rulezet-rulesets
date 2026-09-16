import "pe"
rule ASPack_v2001_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 72 05 00 00 EB 4C }
    condition:
        $a at pe.entry_point

}