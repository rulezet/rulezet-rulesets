import "pe"
rule ACProtect_109g_Risco_software_Inc_additional: PEiD
{
    strings:
        $a = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
    condition:
        $a at pe.entry_point

}