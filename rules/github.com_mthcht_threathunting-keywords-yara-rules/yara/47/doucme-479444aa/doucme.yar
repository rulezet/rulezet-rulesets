rule doucme
{
    meta:
        description = "Detection patterns for the tool 'doucme' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "doucme"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\"NSA0XF\$\\"/ nocase ascii wide
                        $string2 = /\/DoUCMe\.git/ nocase ascii wide
                        $string3 = /\\doucme\.csproj/ nocase ascii wide
                        $string4 = /\\doucme\.exe/ nocase ascii wide
                        $string5 = /\\doucme\.sln/ nocase ascii wide
                        $string6 = "A11E7DAE-21F2-46A8-991E-D38DEBE1650F" nocase ascii wide
                        $string7 = "All Done! Hack the planet!" nocase ascii wide
                        $string8 = "Ben0xA/DoUCMe" nocase ascii wide
                        $string9 = /DoUCMe\-main\\/ nocase ascii wide
                        $string10 = "Enumerating Administrators group, please wait" nocase ascii wide
                        $string11 = "Enumerating new user, please wait" nocase ascii wide
                        $string12 = "PASSWORD = \"Letmein123!" nocase ascii wide

    condition:
        any of them
}