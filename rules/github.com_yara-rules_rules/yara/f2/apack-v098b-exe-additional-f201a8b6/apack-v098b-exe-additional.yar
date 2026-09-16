import "pe"
rule aPack_v098b_exe_additional: PEiD
{
    strings:
        $a = { 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA }
    condition:
        $a at pe.entry_point

}