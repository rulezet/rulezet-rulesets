rule web_hacking_toolkit
{
    meta:
        description = "Detection patterns for the tool 'web-hacking-toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "web-hacking-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " web-hacking-toolkit " nocase ascii wide
                        $string2 = "/web-hacking-toolkit" nocase ascii wide
                        $string3 = /web\-hacking\-toolkit\.git/ nocase ascii wide

    condition:
        any of them
}