rule Adeleginator
{
    meta:
        description = "Detection patterns for the tool 'Adeleginator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adeleginator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADeleg\.exe/ nocase ascii wide
                        $string2 = /\$ADelegReport/ nocase ascii wide
                        $string3 = /\$InsecureResourceDelegations/ nocase ascii wide
                        $string4 = /\$InsecureTrusteeDelegations/ nocase ascii wide
                        $string5 = /\/ADeleg\.exe/ nocase ascii wide
                        $string6 = /\/ADeleginator\.git/ nocase ascii wide
                        $string7 = "/Invoke-Adeleginator" nocase ascii wide
                        $string8 = "/mtth-bfft/adeleg/releases" nocase ascii wide
                        $string9 = /\[\!\]\sInsecure\sresource\sdelegations\sfound\.\sExporting\sreport\:/ nocase ascii wide
                        $string10 = /\[\!\]\sInsecure\strustee\sdelegations\sfound\.\sExporting\sreport\:\s/ nocase ascii wide
                        $string11 = /\[\+\]\sNo\sinsecure\sresource\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
                        $string12 = /\[\+\]\sNo\sinsecure\strustee\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
                        $string13 = /\[i\]\sChecking\sfor\sinsecure\strustee\/resource\sdelegations/ nocase ascii wide
                        $string14 = /\[i\]\sRunning\sADeleg\sand\screating\s/ nocase ascii wide
                        $string15 = /\\ADeleg\.exe/ nocase ascii wide
                        $string16 = /\\Adeleginator\-main/ nocase ascii wide
                        $string17 = "ADeleg_InsecureResourceDelegationReport_" nocase ascii wide
                        $string18 = "ADeleg_InsecureTrusteeDelegationReport_" nocase ascii wide
                        $string19 = "Create-ADelegReport" nocase ascii wide
                        $string20 = "Find-InsecureResourceDelegations" nocase ascii wide
                        $string21 = "Go, go ADeleginator!" nocase ascii wide
                        $string22 = "Invoke-Adeleginator" nocase ascii wide
                        $string23 = "techspence/Adeleginator" nocase ascii wide
                        $string24 = /Thank\syou\sfor\susing\sADeleginator\.\sGodspeed\!\s\:O/ nocase ascii wide

    condition:
        any of them
}