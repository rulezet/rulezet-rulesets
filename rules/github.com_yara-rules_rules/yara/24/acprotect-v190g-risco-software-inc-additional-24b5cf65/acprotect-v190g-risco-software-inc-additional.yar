import "pe"
rule ACProtect_v190g_Risco_software_Inc_additional: PEiD
{
    strings:
        $a = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }
    condition:
        $a at pe.entry_point

}