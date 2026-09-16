import "pe"
rule Microsoft_Windows_Cabinet_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4D 53 43 46 }
    condition:
        $a at pe.entry_point

}