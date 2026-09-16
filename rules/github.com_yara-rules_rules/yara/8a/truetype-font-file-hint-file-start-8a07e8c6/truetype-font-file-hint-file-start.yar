import "pe"
rule TrueType_Font_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 01 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 4C 54 53 48 }
    condition:
        $a at pe.entry_point

}