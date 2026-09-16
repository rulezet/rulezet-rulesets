import "pe"
rule Turbo_Pascal_v60_Unit: PEiD
{
    strings:
        $a = { 54 50 55 39 00 }
    condition:
        $a at pe.entry_point

}