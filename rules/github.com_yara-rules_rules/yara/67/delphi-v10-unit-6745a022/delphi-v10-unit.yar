import "pe"
rule Delphi_v10_Unit: PEiD
{
    strings:
        $a = { 44 43 55 31 }
    condition:
        $a at pe.entry_point

}