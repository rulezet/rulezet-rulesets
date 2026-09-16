import "pe"
rule Hyper_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 1A 48 50 }
    condition:
        $a at pe.entry_point

}