import "pe"
rule EXE_Stealth_v27_WebToolMaster: PEiD
{
    strings:
        $a = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }
    condition:
        $a at pe.entry_point

}