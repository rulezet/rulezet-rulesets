import "pe"
rule TrueVision_Targa_Graphics_format: PEiD
{
    strings:
        $a = { 00 00 02 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}