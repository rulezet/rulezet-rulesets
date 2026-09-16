import "pe"
rule InterGraph_Graphics_format: PEiD
{
    strings:
        $a = { 08 09 FE 01 18 00 00 00 }
    condition:
        $a at pe.entry_point

}