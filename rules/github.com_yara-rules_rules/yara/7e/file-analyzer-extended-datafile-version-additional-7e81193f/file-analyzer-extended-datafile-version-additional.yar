import "pe"
rule File_Analyzer_Extended_Datafile_Version_additional: PEiD
{
    strings:
        $a = { 23 03 45 58 54 44 ?? ?? 3A 03 }
    condition:
        $a at pe.entry_point

}