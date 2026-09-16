import "pe"
rule SQZ_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 48 4C 53 51 5A }
    condition:
        $a at pe.entry_point

}