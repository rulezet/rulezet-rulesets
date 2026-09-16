import "pe"
rule File_Analyzer_Extended_Datafile: PEiD
{
    strings:
        $a = { 23 03 45 58 54 44 }
    condition:
        $a at pe.entry_point

}