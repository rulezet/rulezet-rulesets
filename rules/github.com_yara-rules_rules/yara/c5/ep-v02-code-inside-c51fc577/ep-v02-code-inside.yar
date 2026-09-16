import "pe"
rule EP_v02_CoDe_Inside: PEiD
{
    strings:
        $a = { 6A 00 60 E9 01 01 00 00 }
    condition:
        $a at pe.entry_point

}