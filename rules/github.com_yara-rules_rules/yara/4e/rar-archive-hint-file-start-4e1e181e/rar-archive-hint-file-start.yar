import "pe"
rule RAR_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 61 72 21 }
    condition:
        $a at pe.entry_point

}