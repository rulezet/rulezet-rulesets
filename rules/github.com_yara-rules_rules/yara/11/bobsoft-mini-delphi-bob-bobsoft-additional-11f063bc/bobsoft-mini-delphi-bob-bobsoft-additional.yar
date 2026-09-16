import "pe"
rule BobSoft_Mini_Delphi_BoB_BobSoft_additional: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }
    condition:
        $a at pe.entry_point

}