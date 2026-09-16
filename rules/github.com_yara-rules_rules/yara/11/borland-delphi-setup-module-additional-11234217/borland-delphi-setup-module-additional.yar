import "pe"
rule Borland_Delphi_Setup_Module_additional: PEiD
{
    strings:
        $a = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }
    condition:
        $a at pe.entry_point

}