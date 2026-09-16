import "pe"
rule File_Analyzer_Registration_file_v11: PEiD
{
    strings:
        $a = { 24 46 41 52 45 47 24 45 4E 43 3D ?? 26 26 52 45 47 3D ?? 26 26 45 58 50 3D }
    condition:
        $a at pe.entry_point

}