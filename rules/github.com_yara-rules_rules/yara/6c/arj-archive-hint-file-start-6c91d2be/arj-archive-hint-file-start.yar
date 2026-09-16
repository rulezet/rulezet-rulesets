import "pe"
rule ARJ_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 60 EA }
    condition:
        $a at pe.entry_point

}