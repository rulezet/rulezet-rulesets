import "pe"
rule TIFF_Graphics_file_IBM_Hint_FILE_START: PEiD
{
    strings:
        $a = { 49 49 2A }
    condition:
        $a at pe.entry_point

}