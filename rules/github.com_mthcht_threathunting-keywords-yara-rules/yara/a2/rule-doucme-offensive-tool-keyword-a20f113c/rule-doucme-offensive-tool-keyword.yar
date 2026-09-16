rule rule_doucme_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'doucme' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "doucme"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_doucme_offensive_tool_keyword = /\\"NSA0XF\$\\"/ nocase ascii wide
                        $string2_doucme_offensive_tool_keyword = /\/DoUCMe\.git/ nocase ascii wide
                        $string3_doucme_offensive_tool_keyword = /\\doucme\.csproj/ nocase ascii wide
                        $string4_doucme_offensive_tool_keyword = /\\doucme\.exe/ nocase ascii wide
                        $string5_doucme_offensive_tool_keyword = /\\doucme\.sln/ nocase ascii wide
                        $string6_doucme_offensive_tool_keyword = "A11E7DAE-21F2-46A8-991E-D38DEBE1650F" nocase ascii wide
                        $string7_doucme_offensive_tool_keyword = "All Done! Hack the planet!" nocase ascii wide
                        $string8_doucme_offensive_tool_keyword = "Ben0xA/DoUCMe" nocase ascii wide
                        $string9_doucme_offensive_tool_keyword = /DoUCMe\-main\\/ nocase ascii wide
                        $string10_doucme_offensive_tool_keyword = "Enumerating Administrators group, please wait" nocase ascii wide
                        $string11_doucme_offensive_tool_keyword = "Enumerating new user, please wait" nocase ascii wide
                        $string12_doucme_offensive_tool_keyword = "PASSWORD = \"Letmein123!" nocase ascii wide

    condition:
        any of them
}