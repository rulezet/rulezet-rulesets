import "pe"
rule Thoreador_12_Sergi: PEiD
{
    strings:
        $a = { 55 E8 00 00 00 00 5D 83 ED 06 81 ED E2 00 00 00 60 EB 6F 90 90 90 }
    condition:
        $a at pe.entry_point

}