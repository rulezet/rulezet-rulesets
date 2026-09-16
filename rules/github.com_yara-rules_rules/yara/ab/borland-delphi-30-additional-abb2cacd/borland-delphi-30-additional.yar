import "pe"
rule Borland_Delphi_30_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 }
    condition:
        $a at pe.entry_point

}