import "pe"
rule Goldeds_Output_text_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { C4 20 5B }
    condition:
        $a at pe.entry_point

}