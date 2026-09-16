import "pe"
rule ASPack_108_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 01 FF E9 }
    condition:
        $a at pe.entry_point

}