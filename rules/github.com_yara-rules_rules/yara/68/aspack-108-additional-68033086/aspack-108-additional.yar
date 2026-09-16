import "pe"
rule ASPack_108_additional: PEiD
{
    strings:
        $a = { 90 90 90 75 01 90 E9 }
    condition:
        $a at pe.entry_point

}