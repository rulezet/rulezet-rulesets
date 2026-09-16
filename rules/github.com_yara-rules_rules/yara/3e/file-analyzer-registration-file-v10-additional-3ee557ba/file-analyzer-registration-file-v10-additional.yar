import "pe"
rule File_Analyzer_Registration_file_v10_additional: PEiD
{
    strings:
        $a = { 24 46 41 52 45 47 24 4D 2D ?? ?? ?? ?? 31 }
    condition:
        $a at pe.entry_point

}