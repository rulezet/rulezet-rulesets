import "pe"
rule Turbo_or_Borland_Pascal_v7x_Unit: PEiD
{
    strings:
        $a = { 54 50 55 51 00 }
    condition:
        $a at pe.entry_point

}