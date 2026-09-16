import "pe"
rule ESO_Eclipse_Operating_System_v208_p_DOS_Extender: PEiD
{
    strings:
        $a = { 8C C8 8E D8 BA ?? ?? E8 ?? ?? BB ?? ?? 8C C0 2B D8 B4 4A CD 21 BA ?? ?? 73 ?? E9 }
    condition:
        $a at pe.entry_point

}