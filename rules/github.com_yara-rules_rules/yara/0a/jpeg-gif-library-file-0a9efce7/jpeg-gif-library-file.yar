import "pe"
rule JPEG_GIF_library_file: PEiD
{
    strings:
        $a = { 00 05 16 07 00 02 00 00 }
    condition:
        $a at pe.entry_point

}