import "pe"
rule AIN_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 21 11 00 }
    condition:
        $a at pe.entry_point

}