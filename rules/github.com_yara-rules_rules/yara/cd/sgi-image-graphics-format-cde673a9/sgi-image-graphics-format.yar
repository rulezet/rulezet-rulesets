import "pe"
rule SGI_Image_Graphics_format: PEiD
{
    strings:
        $a = { 01 DA 00 01 00 03 }
    condition:
        $a at pe.entry_point

}