import "pe"
rule Microsoft_Windows_Shortcut_file_additional: PEiD
{
    strings:
        $a = { 4C 00 00 00 01 14 02 00 00 00 }
    condition:
        $a at pe.entry_point

}