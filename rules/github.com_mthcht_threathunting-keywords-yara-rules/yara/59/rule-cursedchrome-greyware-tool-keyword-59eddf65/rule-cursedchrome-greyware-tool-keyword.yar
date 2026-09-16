rule rule_CursedChrome_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_CursedChrome_greyware_tool_keyword = /\/anyproxy\.log/
                        $string2_CursedChrome_greyware_tool_keyword = "/work/anyproxy/bin/anyproxy-ca --generate"
                        $string3_CursedChrome_greyware_tool_keyword = "anyproxy --intercept --ws-intercept " nocase ascii wide

    condition:
        any of them
}