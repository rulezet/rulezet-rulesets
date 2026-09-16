import "pe"
rule Interchange_Format_File_IFF_type_WVQA_Hint_FILE_START: PEiD
{
    strings:
        $a = { 46 4F 52 4D ?? ?? ?? ?? 57 56 51 41 56 51 48 44 }
    condition:
        $a at pe.entry_point

}