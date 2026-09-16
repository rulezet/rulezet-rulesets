import "pe"
rule ASProtect_11_BRS_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E9 ?? 05 00 00 }
    condition:
        $a at pe.entry_point

}