import "pe"
rule Microsoft_Windows_Help_file: PEiD
{
    strings:
        $a = { 3F 5F 03 }
    condition:
        $a at pe.entry_point

}