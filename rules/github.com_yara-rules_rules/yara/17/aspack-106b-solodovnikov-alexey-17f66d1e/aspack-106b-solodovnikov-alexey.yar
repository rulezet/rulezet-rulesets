import "pe"
rule ASPack_106b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 90 75 00 E9 }
    condition:
        $a at pe.entry_point

}