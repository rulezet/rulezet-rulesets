import "pe"
rule aPack_v098b_exe_Hint_HDR_FILESIZE_16: PEiD
{
    strings:
        $a = { 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA }
    condition:
        $a at pe.entry_point

}