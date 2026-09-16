import "pe"
rule File_Analyzer_Registration_file_v10_Hint_FILE_START: PEiD
{
    strings:
        $a = { 24 46 41 52 45 47 24 4D 2D ?? ?? ?? ?? 31 }
    condition:
        $a at pe.entry_point

}