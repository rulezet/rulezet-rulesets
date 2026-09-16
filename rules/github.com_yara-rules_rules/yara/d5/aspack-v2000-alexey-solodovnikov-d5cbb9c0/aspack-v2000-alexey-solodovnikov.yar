import "pe"
rule ASPack_v2000_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 70 05 00 00 EB 4C }
    condition:
        $a at pe.entry_point

}