import "pe"
rule X_Pack_v142_Hint_HDR_FILESIZE_32: PEiD
{
    strings:
        $a = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }
    condition:
        $a at pe.entry_point

}