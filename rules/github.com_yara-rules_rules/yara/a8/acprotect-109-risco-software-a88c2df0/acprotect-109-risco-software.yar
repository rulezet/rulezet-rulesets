import "pe"
rule ACProtect_109_Risco_Software: PEiD
{
    strings:
        $a = { 60 E8 01 00 00 00 E8 83 C4 04 85 DF E8 01 00 00 00 76 83 04 24 06 C3 0F 81 02 00 00 }
    condition:
        $a at pe.entry_point

}