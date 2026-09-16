import "pe"
rule DWC_Archive_Hint_DOS_FILESIZE_3: PEiD
{
    strings:
        $a = { 44 57 43 }
    condition:
        $a at pe.entry_point

}