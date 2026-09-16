import "pe"
rule May_be_Pklite_Header_Version_v6v2_extra_0_v5_1_Hint_HDR_END: PEiD
{
    strings:
        $a = { 50 4B }
    condition:
        $a at pe.entry_point

}