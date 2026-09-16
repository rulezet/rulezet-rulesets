import "pe"
rule Microsoft_Windows_Metafile_Hint_FILE_START: PEiD
{
    strings:
        $a = { D7 CD C6 9A }
    condition:
        $a at pe.entry_point

}