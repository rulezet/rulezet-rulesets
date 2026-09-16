import "pe"
rule Microsoft_Bitmap_Graphics_format: PEiD
{
    strings:
        $a = { 01 00 09 00 }
    condition:
        $a at pe.entry_point

}