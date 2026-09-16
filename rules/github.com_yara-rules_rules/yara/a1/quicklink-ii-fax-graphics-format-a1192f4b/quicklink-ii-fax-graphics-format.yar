import "pe"
rule QuickLink_II_Fax_Graphics_format: PEiD
{
    strings:
        $a = { 51 4C 49 49 46 41 58 20 }
    condition:
        $a at pe.entry_point

}