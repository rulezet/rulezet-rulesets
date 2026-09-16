import "pe"
rule Stelth_PE_101_BGCorp_additional: PEiD
{
    strings:
        $a = { BA ?? ?? ?? 00 }
    condition:
        $a at pe.entry_point

}