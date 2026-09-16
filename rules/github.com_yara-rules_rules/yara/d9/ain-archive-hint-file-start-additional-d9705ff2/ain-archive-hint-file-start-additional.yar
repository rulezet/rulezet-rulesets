import "pe"
rule AIN_Archive_Hint_FILE_START_additional: PEiD
{
    strings:
        $a = { 21 12 00 }
    condition:
        $a at pe.entry_point

}