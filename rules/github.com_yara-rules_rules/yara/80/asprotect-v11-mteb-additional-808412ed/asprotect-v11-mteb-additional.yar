import "pe"
rule ASProtect_v11_MTEb_additional: PEiD
{
    strings:
        $a = { 90 60 E9 ?? 04 }
    condition:
        $a at pe.entry_point

}