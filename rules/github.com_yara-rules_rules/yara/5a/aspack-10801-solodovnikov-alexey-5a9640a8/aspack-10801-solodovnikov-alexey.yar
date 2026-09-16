import "pe"
rule ASPack_10801_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 ?? 90 E9 }
    condition:
        $a at pe.entry_point

}