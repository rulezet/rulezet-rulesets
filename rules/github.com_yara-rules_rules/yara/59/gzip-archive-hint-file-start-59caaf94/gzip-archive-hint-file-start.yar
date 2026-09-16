import "pe"
rule GZIP_Archive_Hint_FILE_START: PEiD
{
    strings:
        $a = { 1F 8B 08 08 ?? ?? ?? 35 }
    condition:
        $a at pe.entry_point

}