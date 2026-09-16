import "pe"
rule EXE_Stealth_v11: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }
    condition:
        $a at pe.entry_point

}