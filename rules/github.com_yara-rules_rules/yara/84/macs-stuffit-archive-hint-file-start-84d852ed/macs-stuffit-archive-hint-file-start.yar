import "pe"
rule Macs_StuffIt_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 53 49 54 21 00 }
    condition:
        $a at pe.entry_point

}