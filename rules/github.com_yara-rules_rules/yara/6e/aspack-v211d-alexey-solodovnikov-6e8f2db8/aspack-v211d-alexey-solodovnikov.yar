import "pe"
rule ASPack_v211d_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 02 00 00 00 EB 09 5D 55 }
    condition:
        $a at pe.entry_point

}