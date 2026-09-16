import "pe"
rule File_Analyzer_Compiled_Datafile_Version_additional: PEiD
{
    strings:
        $a = { 46 69 6C 65 20 41 6E 61 6C 79 7A 65 72 20 43 6F 6D 70 69 6C 65 64 20 44 61 74 61 66 69 6C 65 20 56 65 72 73 69 6F 6E }
    condition:
        $a at pe.entry_point

}