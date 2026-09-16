import "pe"
rule CalComp_Graphics_format: PEiD
{
    strings:
        $a = { 02 50 0A }
    condition:
        $a at pe.entry_point

}