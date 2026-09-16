import "pe"
rule LHA_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 6C 68 35 }
    condition:
        $a at pe.entry_point

}