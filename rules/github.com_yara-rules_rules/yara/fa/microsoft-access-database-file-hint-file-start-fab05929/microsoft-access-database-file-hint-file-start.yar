import "pe"
rule Microsoft_Access_Database_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 00 }
    condition:
        $a at pe.entry_point

}