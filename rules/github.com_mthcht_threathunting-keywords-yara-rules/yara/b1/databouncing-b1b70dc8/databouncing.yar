rule DataBouncing
{
    meta:
        description = "Detection patterns for the tool 'DataBouncing' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DataBouncing"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdeadPool\.ps1/ nocase ascii wide
                        $string2 = /\sexfilGui\.ps1/ nocase ascii wide
                        $string3 = /\snightCrawler\.ps1/ nocase ascii wide
                        $string4 = /\swget\s\\"https\:\/\/.{0,1000}\/interactshbuild/ nocase ascii wide
                        $string5 = /\/DataBouncing\.git/ nocase ascii wide
                        $string6 = /\/deadPool\.ps1/ nocase ascii wide
                        $string7 = /\/exfilGui\.ps1/ nocase ascii wide
                        $string8 = /\/nightCrawler\.ps1/ nocase ascii wide
                        $string9 = /\\deadPool\.ps1/ nocase ascii wide
                        $string10 = /\\exfilGui\.ps1/ nocase ascii wide
                        $string11 = /\\nightCrawler\.ps1/ nocase ascii wide
                        $string12 = /bash\s\.\/bounce\.sh/
                        $string13 = /clndh3qilvdv6403g1n0hs3rhd6xpfmjn\.oast\.online/ nocase ascii wide
                        $string14 = /DataBouncing\-main\.zip/ nocase ascii wide
                        $string15 = /exfil\s\-regex.{0,1000}\s\-domain.{0,1000}\-url\s.{0,1000}\s\-filepath\s/ nocase ascii wide
                        $string16 = /Find\-Secret\s\-FilePath\s\.\/logs\.txt\s\-Regex\s/
                        $string17 = /https\:\/\/unit259\.fyi\/db/ nocase ascii wide
                        $string18 = /irm\sunit259\.fyi\/dbgui\s\|\siex/ nocase ascii wide
                        $string19 = /nightCrawler\.ps1\s/ nocase ascii wide
                        $string20 = "Unit-259/DataBouncing" nocase ascii wide

    condition:
        any of them
}