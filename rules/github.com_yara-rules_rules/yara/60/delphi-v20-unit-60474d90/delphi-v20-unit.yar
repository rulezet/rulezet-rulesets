import "pe"
rule Delphi_v20_Unit: PEiD
{
    strings:
        $a = { 44 43 55 32 }
    condition:
        $a at pe.entry_point

}