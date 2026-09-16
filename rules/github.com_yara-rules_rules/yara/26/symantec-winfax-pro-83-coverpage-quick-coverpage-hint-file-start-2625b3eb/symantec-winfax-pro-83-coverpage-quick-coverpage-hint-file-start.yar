import "pe"
rule Symantec_WinFax_PRO_83_Coverpage_Quick_CoverPage_Hint_FILE_START: PEiD
{
    strings:
        $a = { FF FF ?? ?? ?? ?? ?? 43 6F 76 65 72 44 61 74 61 62 61 73 65 }
    condition:
        $a at pe.entry_point

}