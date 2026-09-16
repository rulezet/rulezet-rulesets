rule rule_PasswordHashesView_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PasswordHashesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PasswordHashesView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PasswordHashesView_offensive_tool_keyword = ">PasswordHashesView<" nocase ascii wide
                        $string2_PasswordHashesView_offensive_tool_keyword = /PasswordHashesView\.exe/ nocase ascii wide
                        $string3_PasswordHashesView_offensive_tool_keyword = /passwordhashesview\.zip/ nocase ascii wide
                        $string4_PasswordHashesView_offensive_tool_keyword = /passwordhashesview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}