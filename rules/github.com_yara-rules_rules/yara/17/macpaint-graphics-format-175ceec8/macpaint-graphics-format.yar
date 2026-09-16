import "pe"
rule MacPaint_Graphics_format: PEiD
{
    strings:
        $a = { 00 00 00 02 FF FF FF FF }
    condition:
        $a at pe.entry_point

}