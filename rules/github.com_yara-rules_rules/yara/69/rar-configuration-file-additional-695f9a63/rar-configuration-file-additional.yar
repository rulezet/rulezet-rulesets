import "pe"
rule RAR_Configuration_file_additional: PEiD
{
    strings:
        $a = { 52 41 52 20 43 4F 4E 46 49 47 }
    condition:
        $a at pe.entry_point

}