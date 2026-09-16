import "pe"
rule pex_V099_params: PEiD
{
    strings:
        $a = { E9 F5 00 00 00 }
    condition:
        $a at pe.entry_point

}