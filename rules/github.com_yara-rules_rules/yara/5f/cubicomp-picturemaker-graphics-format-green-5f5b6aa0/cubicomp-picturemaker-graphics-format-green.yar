import "pe"
rule CubiComp_PictureMaker_graphics_format_green: PEiD
{
    strings:
        $a = { 26 0C FF 02 00 00 00 00 }
    condition:
        $a at pe.entry_point

}