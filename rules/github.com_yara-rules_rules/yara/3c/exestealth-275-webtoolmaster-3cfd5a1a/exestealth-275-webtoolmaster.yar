import "pe"
rule EXEStealth_275_WebtoolMaster: PEiD
{
    strings:
        $a = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }
    condition:
        $a at pe.entry_point

}