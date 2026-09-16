rule rule_whoami_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_whoami_offensive_tool_keyword = /\\x2f\\x75\\x73\\x72\\x2f\\x62\\x69\\x6e\\x2f\\x77\\x68\\x6f\\x61\\x6d\\x69/ nocase ascii wide
                        $string2_whoami_offensive_tool_keyword = "imaohw/nib/rsu/" nocase ascii wide
                        $string3_whoami_offensive_tool_keyword = "L3Vzci9iaW4vd2hvYW1p" nocase ascii wide

    condition:
        any of them
}