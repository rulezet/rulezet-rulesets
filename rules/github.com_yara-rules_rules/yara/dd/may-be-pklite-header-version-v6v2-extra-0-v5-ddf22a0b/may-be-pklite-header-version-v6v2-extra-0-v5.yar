import "pe"
rule May_be_Pklite_Header_Version_v6v2_extra_0_v5: PEiD
{
    strings:
        $a = { ?? ?? 50 6B }
        $b = { ?? ?? 50 4B }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}