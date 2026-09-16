rule csploit
{
    meta:
        description = "Detection patterns for the tool 'csploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /cSploit\-.{0,1000}\.apk/ nocase ascii wide
                        $string2 = "cSploit/android" nocase ascii wide

    condition:
        any of them
}