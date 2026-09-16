import "pe"
rule Packed_with_PKLITE_v150_with_CRC_check_1_Hint_DOS_EP_p_146: PEiD
{
    strings:
        $a = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }
    condition:
        $a at pe.entry_point

}