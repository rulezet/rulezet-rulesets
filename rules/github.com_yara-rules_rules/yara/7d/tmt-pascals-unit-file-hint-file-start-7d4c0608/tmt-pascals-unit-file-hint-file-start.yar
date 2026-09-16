import "pe"
rule TMT_Pascals_Unit_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 00 00 00 53 50 46 50 }
    condition:
        $a at pe.entry_point

}