import "pe"
rule Hyper_Archive_Hint_FILE_START_additional: PEiD
{
    strings:
        $a = { 1A 53 54 }
    condition:
        $a at pe.entry_point

}