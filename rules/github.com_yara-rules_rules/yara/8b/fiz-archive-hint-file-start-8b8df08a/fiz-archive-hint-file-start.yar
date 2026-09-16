import "pe"
rule FIZ_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 46 49 5A 1A 01 }
    condition:
        $a at pe.entry_point

}