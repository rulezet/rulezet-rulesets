rule PasswordHashesView
{
    meta:
        description = "Detection patterns for the tool 'PasswordHashesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PasswordHashesView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = ">PasswordHashesView<" nocase ascii wide
                        $string2 = /PasswordHashesView\.exe/ nocase ascii wide
                        $string3 = /passwordhashesview\.zip/ nocase ascii wide
                        $string4 = /passwordhashesview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}