import "pe"
rule DrWeb_Virus_Finding_Engine_InSoft_EDV_Systeme: PEiD
{
    strings:
        $a = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }
    condition:
        $a at pe.entry_point

}