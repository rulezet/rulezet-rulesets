rule rule_Adeleginator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Adeleginator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adeleginator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Adeleginator_offensive_tool_keyword = /\sADeleg\.exe/ nocase ascii wide
                        $string2_Adeleginator_offensive_tool_keyword = /\$ADelegReport/ nocase ascii wide
                        $string3_Adeleginator_offensive_tool_keyword = /\$InsecureResourceDelegations/ nocase ascii wide
                        $string4_Adeleginator_offensive_tool_keyword = /\$InsecureTrusteeDelegations/ nocase ascii wide
                        $string5_Adeleginator_offensive_tool_keyword = /\/ADeleg\.exe/ nocase ascii wide
                        $string6_Adeleginator_offensive_tool_keyword = /\/ADeleginator\.git/ nocase ascii wide
                        $string7_Adeleginator_offensive_tool_keyword = "/Invoke-Adeleginator" nocase ascii wide
                        $string8_Adeleginator_offensive_tool_keyword = "/mtth-bfft/adeleg/releases" nocase ascii wide
                        $string9_Adeleginator_offensive_tool_keyword = /\[\!\]\sInsecure\sresource\sdelegations\sfound\.\sExporting\sreport\:/ nocase ascii wide
                        $string10_Adeleginator_offensive_tool_keyword = /\[\!\]\sInsecure\strustee\sdelegations\sfound\.\sExporting\sreport\:\s/ nocase ascii wide
                        $string11_Adeleginator_offensive_tool_keyword = /\[\+\]\sNo\sinsecure\sresource\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
                        $string12_Adeleginator_offensive_tool_keyword = /\[\+\]\sNo\sinsecure\strustee\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
                        $string13_Adeleginator_offensive_tool_keyword = /\[i\]\sChecking\sfor\sinsecure\strustee\/resource\sdelegations/ nocase ascii wide
                        $string14_Adeleginator_offensive_tool_keyword = /\[i\]\sRunning\sADeleg\sand\screating\s/ nocase ascii wide
                        $string15_Adeleginator_offensive_tool_keyword = /\\ADeleg\.exe/ nocase ascii wide
                        $string16_Adeleginator_offensive_tool_keyword = /\\Adeleginator\-main/ nocase ascii wide
                        $string17_Adeleginator_offensive_tool_keyword = "ADeleg_InsecureResourceDelegationReport_" nocase ascii wide
                        $string18_Adeleginator_offensive_tool_keyword = "ADeleg_InsecureTrusteeDelegationReport_" nocase ascii wide
                        $string19_Adeleginator_offensive_tool_keyword = "Create-ADelegReport" nocase ascii wide
                        $string20_Adeleginator_offensive_tool_keyword = "Find-InsecureResourceDelegations" nocase ascii wide
                        $string21_Adeleginator_offensive_tool_keyword = "Go, go ADeleginator!" nocase ascii wide
                        $string22_Adeleginator_offensive_tool_keyword = "Invoke-Adeleginator" nocase ascii wide
                        $string23_Adeleginator_offensive_tool_keyword = "techspence/Adeleginator" nocase ascii wide
                        $string24_Adeleginator_offensive_tool_keyword = /Thank\syou\sfor\susing\sADeleginator\.\sGodspeed\!\s\:O/ nocase ascii wide

    condition:
        any of them
}