import "pe"
rule MS_HTML_Help_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 49 54 53 46 }
    condition:
        $a at pe.entry_point

}