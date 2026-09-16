rule rule_DataBouncing_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DataBouncing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DataBouncing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DataBouncing_offensive_tool_keyword = /\sdeadPool\.ps1/ nocase ascii wide
                        $string2_DataBouncing_offensive_tool_keyword = /\sexfilGui\.ps1/ nocase ascii wide
                        $string3_DataBouncing_offensive_tool_keyword = /\snightCrawler\.ps1/ nocase ascii wide
                        $string4_DataBouncing_offensive_tool_keyword = /\swget\s\\"https\:\/\/.{0,1000}\/interactshbuild/ nocase ascii wide
                        $string5_DataBouncing_offensive_tool_keyword = /\/DataBouncing\.git/ nocase ascii wide
                        $string6_DataBouncing_offensive_tool_keyword = /\/deadPool\.ps1/ nocase ascii wide
                        $string7_DataBouncing_offensive_tool_keyword = /\/exfilGui\.ps1/ nocase ascii wide
                        $string8_DataBouncing_offensive_tool_keyword = /\/nightCrawler\.ps1/ nocase ascii wide
                        $string9_DataBouncing_offensive_tool_keyword = /\\deadPool\.ps1/ nocase ascii wide
                        $string10_DataBouncing_offensive_tool_keyword = /\\exfilGui\.ps1/ nocase ascii wide
                        $string11_DataBouncing_offensive_tool_keyword = /\\nightCrawler\.ps1/ nocase ascii wide
                        $string12_DataBouncing_offensive_tool_keyword = /bash\s\.\/bounce\.sh/
                        $string13_DataBouncing_offensive_tool_keyword = /clndh3qilvdv6403g1n0hs3rhd6xpfmjn\.oast\.online/ nocase ascii wide
                        $string14_DataBouncing_offensive_tool_keyword = /DataBouncing\-main\.zip/ nocase ascii wide
                        $string15_DataBouncing_offensive_tool_keyword = /exfil\s\-regex.{0,1000}\s\-domain.{0,1000}\-url\s.{0,1000}\s\-filepath\s/ nocase ascii wide
                        $string16_DataBouncing_offensive_tool_keyword = /Find\-Secret\s\-FilePath\s\.\/logs\.txt\s\-Regex\s/
                        $string17_DataBouncing_offensive_tool_keyword = /https\:\/\/unit259\.fyi\/db/ nocase ascii wide
                        $string18_DataBouncing_offensive_tool_keyword = /irm\sunit259\.fyi\/dbgui\s\|\siex/ nocase ascii wide
                        $string19_DataBouncing_offensive_tool_keyword = /nightCrawler\.ps1\s/ nocase ascii wide
                        $string20_DataBouncing_offensive_tool_keyword = "Unit-259/DataBouncing" nocase ascii wide

    condition:
        any of them
}