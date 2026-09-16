import "pe"
rule EXE_Stealth_v26_WebToolMaster: PEiD
{
    strings:
        $a = { 60 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 }
    condition:
        $a at pe.entry_point

}