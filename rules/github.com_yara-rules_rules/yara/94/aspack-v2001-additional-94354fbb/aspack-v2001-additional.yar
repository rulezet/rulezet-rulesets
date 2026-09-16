import "pe"
rule ASPack_v2001_additional: PEiD
{
    strings:
        $a = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
    condition:
        $a at pe.entry_point

}