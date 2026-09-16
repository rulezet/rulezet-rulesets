import "pe"
rule ExeSmasher: PEiD
{
    strings:
        $a = { 9C FE 03 00 60 BE 00 00 41 00 8D BE 00 10 FF FF 57 83 CD FF EB 10 }
    condition:
        $a at pe.entry_point

}