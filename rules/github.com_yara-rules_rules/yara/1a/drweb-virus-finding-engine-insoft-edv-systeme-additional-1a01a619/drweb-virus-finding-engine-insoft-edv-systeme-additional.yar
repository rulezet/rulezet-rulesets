import "pe"
rule DrWeb_Virus_Finding_Engine_InSoft_EDV_Systeme_additional: PEiD
{
    strings:
        $a = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }
    condition:
        $a at pe.entry_point

}