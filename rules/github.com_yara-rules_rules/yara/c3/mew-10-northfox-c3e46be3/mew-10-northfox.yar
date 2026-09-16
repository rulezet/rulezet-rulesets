import "pe"
rule MEW_10_Northfox: PEiD
{
    strings:
        $a = { 33 C0 E9 }
    condition:
        $a at pe.entry_point

}