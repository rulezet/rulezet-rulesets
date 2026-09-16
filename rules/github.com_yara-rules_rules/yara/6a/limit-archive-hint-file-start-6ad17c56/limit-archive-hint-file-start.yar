import "pe"
rule Limit_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4C 4D 1A }
    condition:
        $a at pe.entry_point

}