import "pe"
rule Microsoft_Resource_Cursors_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 02 00 01 00 20 20 00 00 ?? 00 ?? 00 E8 02 00 00 16 }
    condition:
        $a at pe.entry_point

}