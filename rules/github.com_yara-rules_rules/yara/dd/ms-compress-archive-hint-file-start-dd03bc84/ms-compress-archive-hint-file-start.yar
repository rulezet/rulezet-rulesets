import "pe"
rule MS_Compress_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 53 5A 44 44 }
    condition:
        $a at pe.entry_point

}