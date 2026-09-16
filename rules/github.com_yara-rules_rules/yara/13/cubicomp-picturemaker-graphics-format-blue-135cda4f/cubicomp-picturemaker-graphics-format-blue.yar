import "pe"
rule CubiComp_PictureMaker_graphics_format_blue: PEiD
{
    strings:
        $a = { 36 0C FF 02 00 00 00 00 }
    condition:
        $a at pe.entry_point

}