import "pe"
rule Borland_Delphi_Component_additional: PEiD
{
    strings:
        $a = { C3 E9 ?? ?? ?? FF 8D 40 }
    condition:
        $a at pe.entry_point

}