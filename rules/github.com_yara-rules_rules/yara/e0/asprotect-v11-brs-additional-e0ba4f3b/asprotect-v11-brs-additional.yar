import "pe"
rule ASProtect_v11_BRS_additional: PEiD
{
    strings:
        $a = { 60 E9 ?? 05 }
    condition:
        $a at pe.entry_point

}