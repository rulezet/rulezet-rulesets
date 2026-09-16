import "pe"
rule Datafile_from_Norton_Utilities_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 4E 43 49 }
    condition:
        $a at pe.entry_point

}