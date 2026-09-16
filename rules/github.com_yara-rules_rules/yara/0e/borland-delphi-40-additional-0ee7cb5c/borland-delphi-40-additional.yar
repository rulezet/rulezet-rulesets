import "pe"
rule Borland_Delphi_40_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 }
    condition:
        $a at pe.entry_point

}