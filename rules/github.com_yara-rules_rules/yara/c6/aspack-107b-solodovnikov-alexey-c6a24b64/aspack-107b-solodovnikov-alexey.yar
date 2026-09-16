import "pe"
rule ASPack_107b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 ?? E9 }
    condition:
        $a at pe.entry_point

}