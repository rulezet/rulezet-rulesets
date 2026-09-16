import "pe"
rule Trilobytes_JPEG_graphics_Library_Hint_FILE_START: PEiD
{
    strings:
        $a = { 84 10 FF FF FF FF 1E 00 01 10 08 00 00 00 00 00 }
    condition:
        $a at pe.entry_point

}