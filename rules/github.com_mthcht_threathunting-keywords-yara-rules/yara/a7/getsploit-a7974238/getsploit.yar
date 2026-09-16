rule getsploit
{
    meta:
        description = "Detection patterns for the tool 'getsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "getsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "getsploit" nocase ascii wide

    condition:
        any of them
}