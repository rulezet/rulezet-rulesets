rule rule_KeeTheft_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KeeTheft' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeeTheft"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KeeTheft_offensive_tool_keyword = " Found a PwDatabase! " nocase ascii wide
                        $string2_KeeTheft_offensive_tool_keyword = /\/KeeTheft\.exe/ nocase ascii wide
                        $string3_KeeTheft_offensive_tool_keyword = /\\KeeTheft\.exe/ nocase ascii wide
                        $string4_KeeTheft_offensive_tool_keyword = ">KeeTheft<" nocase ascii wide

    condition:
        any of them
}