import "pe"
rule Borland_Delphi_60_70: PEiD
{
    strings:
        $a = { 55 8B EC B9 07 00 00 }
    condition:
        $a at pe.entry_point

}