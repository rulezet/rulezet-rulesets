import "pe"
rule Borland_Graphics_Interface_Driver: PEiD
{
    strings:
        $a = { 46 42 47 44 }
    condition:
        $a at pe.entry_point

}