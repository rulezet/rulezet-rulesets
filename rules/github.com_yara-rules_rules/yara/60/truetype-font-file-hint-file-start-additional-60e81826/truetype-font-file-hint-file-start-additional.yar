import "pe"
rule TrueType_Font_file_Hint_FILE_START_additional: PEiD
{
    strings:
        $a = { 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4F 53 2F 32 }
    condition:
        $a at pe.entry_point

}