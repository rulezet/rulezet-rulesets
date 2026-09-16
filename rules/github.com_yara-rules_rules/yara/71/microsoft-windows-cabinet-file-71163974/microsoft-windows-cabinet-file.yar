import "pe"
rule Microsoft_Windows_Cabinet_file: PEiD
{
    strings:
        $a = { 4D 53 43 46 }
    condition:
        $a at pe.entry_point

}