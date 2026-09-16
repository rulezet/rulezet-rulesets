import "pe"
rule ACE_SFX_Archive_Hint_HDR_FILESIZE_p_7: PEiD
{
    strings:
        $a = { 2A 2A 41 43 45 2A 2A }
    condition:
        $a at pe.entry_point

}