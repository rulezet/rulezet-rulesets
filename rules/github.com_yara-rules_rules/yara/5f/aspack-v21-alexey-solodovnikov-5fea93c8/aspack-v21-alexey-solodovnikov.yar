import "pe"
rule ASPack_v21_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
    condition:
        $a at pe.entry_point

}