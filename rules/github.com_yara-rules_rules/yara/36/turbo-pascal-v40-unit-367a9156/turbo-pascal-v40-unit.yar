import "pe"
rule Turbo_Pascal_v40_Unit: PEiD
{
    strings:
        $a = { 54 50 55 30 00 }
    condition:
        $a at pe.entry_point

}