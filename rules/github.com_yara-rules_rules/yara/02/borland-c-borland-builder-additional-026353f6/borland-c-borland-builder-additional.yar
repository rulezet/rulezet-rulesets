import "pe"
rule Borland_C_Borland_Builder_additional: PEiD
{
    strings:
        $a = { 3B CF 76 05 2B CF FC F3 AA 59 }
    condition:
        $a at pe.entry_point

}