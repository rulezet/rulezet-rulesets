import "pe"
rule Windows_9x_registry_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 43 52 45 47 }
    condition:
        $a at pe.entry_point

}