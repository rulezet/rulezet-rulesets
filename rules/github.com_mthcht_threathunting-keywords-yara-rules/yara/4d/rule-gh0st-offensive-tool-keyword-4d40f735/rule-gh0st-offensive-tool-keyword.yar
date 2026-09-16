rule rule_gh0st_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gh0st' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gh0st"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gh0st_offensive_tool_keyword = "\"Gh0st RAT Exception\"" nocase ascii wide
                        $string2_gh0st_offensive_tool_keyword = /\/gh0st\.exe/ nocase ascii wide
                        $string3_gh0st_offensive_tool_keyword = /\/gh0st\.git/ nocase ascii wide
                        $string4_gh0st_offensive_tool_keyword = /\/svchost_console\.exe/ nocase ascii wide
                        $string5_gh0st_offensive_tool_keyword = /\\gh0st\.exe/ nocase ascii wide
                        $string6_gh0st_offensive_tool_keyword = /\\svchost_console\.exe/ nocase ascii wide
                        $string7_gh0st_offensive_tool_keyword = "0228336A-2F4C-0D17-2E11-86654A1FAD8D" nocase ascii wide
                        $string8_gh0st_offensive_tool_keyword = "64D26B66-8A59-0724-007F-9001C4F472A2" nocase ascii wide
                        $string9_gh0st_offensive_tool_keyword = "80ABA1A7-0E3E-3DB2-8EB9-D4EE1C266504" nocase ascii wide
                        $string10_gh0st_offensive_tool_keyword = "91283687ba9f56c07f0664807a9387edd6f40e50607fc3c757bcd34b28eb1cd8" nocase ascii wide
                        $string11_gh0st_offensive_tool_keyword = /kstowell\@codejockeys\.com/ nocase ascii wide
                        $string12_gh0st_offensive_tool_keyword = "sin5678/gh0st" nocase ascii wide
                        $string13_gh0st_offensive_tool_keyword = /wolfexp\.net\/other\/Gh0st_RAT\/demo\.rar/ nocase ascii wide

    condition:
        any of them
}