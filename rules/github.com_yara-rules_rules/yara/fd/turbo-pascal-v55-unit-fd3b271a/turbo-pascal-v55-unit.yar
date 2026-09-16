import "pe"
rule Turbo_Pascal_v55_Unit: PEiD
{
    strings:
        $a = { 54 50 55 36 00 }
    condition:
        $a at pe.entry_point

}