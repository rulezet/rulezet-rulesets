rule CursedChrome
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/anyproxy\.log/
                        $string2 = "/work/anyproxy/bin/anyproxy-ca --generate"
                        $string3 = "anyproxy --intercept --ws-intercept " nocase ascii wide

    condition:
        any of them
}