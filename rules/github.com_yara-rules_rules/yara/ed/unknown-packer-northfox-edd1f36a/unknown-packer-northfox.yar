import "pe"
rule Unknown_Packer_Northfox: PEiD
{
    strings:
        $a = { 54 59 68 61 7A 79 }
    condition:
        $a at pe.entry_point

}