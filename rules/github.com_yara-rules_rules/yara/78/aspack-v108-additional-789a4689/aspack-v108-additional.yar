import "pe"
rule ASPack_v108_additional: PEiD
{
    strings:
        $a = { 90 75 01 FF E9 }
    condition:
        $a at pe.entry_point

}