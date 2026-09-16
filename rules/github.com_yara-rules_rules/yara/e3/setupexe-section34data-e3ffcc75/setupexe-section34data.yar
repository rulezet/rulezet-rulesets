import "pe"
rule setupexe_Section34data: PEiD
{
    strings:
        $a = { 80 16 42 00 48 05 44 00 00 00 00 00 2E 3F 41 56 5F 63 6F 6D 5F 65 72 }
    condition:
        $a at pe.entry_point

}