import "pe"
rule IBM_IOCA_Graphics_format: PEiD
{
    strings:
        $a = { 00 11 D3 A6 FB }
    condition:
        $a at pe.entry_point

}