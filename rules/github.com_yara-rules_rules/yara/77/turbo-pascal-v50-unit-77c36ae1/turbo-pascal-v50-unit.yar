import "pe"
rule Turbo_Pascal_v50_Unit: PEiD
{
    strings:
        $a = { 54 50 55 35 00 }
    condition:
        $a at pe.entry_point

}