import "pe"
rule HA_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 48 41 }
    condition:
        $a at pe.entry_point

}