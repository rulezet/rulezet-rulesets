import "pe"
rule ARVIDs_TDR_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 74 00 00 00 }
    condition:
        $a at pe.entry_point

}