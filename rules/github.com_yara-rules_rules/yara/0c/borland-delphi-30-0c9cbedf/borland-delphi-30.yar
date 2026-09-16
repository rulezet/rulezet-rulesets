import "pe"
rule Borland_Delphi_30_: PEiD
{
    strings:
        $a = { 55 8B EC 83 }
    condition:
        $a at pe.entry_point

}