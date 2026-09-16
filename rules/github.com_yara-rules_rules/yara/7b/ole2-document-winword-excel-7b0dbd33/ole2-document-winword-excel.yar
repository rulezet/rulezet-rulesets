import "pe"
rule OLE2_Document_WinWord_Excel_: PEiD
{
    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $a at pe.entry_point

}