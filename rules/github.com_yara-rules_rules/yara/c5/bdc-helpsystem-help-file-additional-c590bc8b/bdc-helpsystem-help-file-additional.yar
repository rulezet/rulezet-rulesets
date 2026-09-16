import "pe"
rule BDC_HelpSystem_Help_file_additional: PEiD
{
    strings:
        $a = { 42 44 43 20 48 65 6C 70 53 79 73 74 65 6D }
    condition:
        $a at pe.entry_point

}