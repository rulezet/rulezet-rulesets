rule rule_CMLoot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CMLoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CMLoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_CMLoot_offensive_tool_keyword = /\sCMLoot\.ps1/ nocase ascii wide
                        $string2_CMLoot_offensive_tool_keyword = /\s\-SCCMHost\s.{0,1000}\s\-Outfile\s/ nocase ascii wide
                        $string3_CMLoot_offensive_tool_keyword = /\/CMLoot\.git/ nocase ascii wide
                        $string4_CMLoot_offensive_tool_keyword = /\/CMLoot\.ps1/ nocase ascii wide
                        $string5_CMLoot_offensive_tool_keyword = /\\CMLoot\.ps1/ nocase ascii wide
                        $string6_CMLoot_offensive_tool_keyword = "1njected/CMLoot" nocase ascii wide
                        $string7_CMLoot_offensive_tool_keyword = /CMLoot\.psm1/ nocase ascii wide
                        $string8_CMLoot_offensive_tool_keyword = "CMLoot-main" nocase ascii wide
                        $string9_CMLoot_offensive_tool_keyword = "Invoke-CMLootDownload" nocase ascii wide
                        $string10_CMLoot_offensive_tool_keyword = "Invoke-CMLootExtract" nocase ascii wide
                        $string11_CMLoot_offensive_tool_keyword = "Invoke-CMLootHunt " nocase ascii wide
                        $string12_CMLoot_offensive_tool_keyword = "Invoke-CMLootInventory" nocase ascii wide
                        $string13_CMLoot_offensive_tool_keyword = /src\\CMLootOut\\/ nocase ascii wide

    condition:
        any of them
}