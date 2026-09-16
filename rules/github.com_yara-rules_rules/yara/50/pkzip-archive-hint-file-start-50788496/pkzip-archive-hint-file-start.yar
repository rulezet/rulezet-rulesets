import "pe"
rule PKZIP_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 4B 03 04 }
    condition:
        $a at pe.entry_point

}