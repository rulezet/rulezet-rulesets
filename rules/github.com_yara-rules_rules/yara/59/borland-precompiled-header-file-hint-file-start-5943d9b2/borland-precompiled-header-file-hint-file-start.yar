import "pe"
rule Borland_precompiled_header_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 54 50 53 }
    condition:
        $a at pe.entry_point

}