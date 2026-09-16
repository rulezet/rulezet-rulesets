import "pe"
rule OAZ_Fax_Graphics_format: PEiD
{
    strings:
        $a = { 0F 0F 0F 0F 01 00 00 00 }
    condition:
        $a at pe.entry_point

}