import "pe"
rule ASPack_v10804_Alexey_Solodovnikov: PEiD
{
    strings:
        $a = { 60 E8 41 06 00 00 EB 41 }
    condition:
        $a at pe.entry_point

}