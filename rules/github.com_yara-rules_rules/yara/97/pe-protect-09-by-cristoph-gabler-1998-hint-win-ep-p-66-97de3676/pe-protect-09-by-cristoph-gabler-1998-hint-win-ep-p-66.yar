import "pe"
rule PE_Protect_09_by_Cristoph_Gabler_1998_Hint_WIN_EP_p_66: PEiD
{
    strings:
        $a = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }
    condition:
        $a at pe.entry_point

}