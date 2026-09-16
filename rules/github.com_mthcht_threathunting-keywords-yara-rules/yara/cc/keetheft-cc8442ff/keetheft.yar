rule KeeTheft
{
    meta:
        description = "Detection patterns for the tool 'KeeTheft' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeeTheft"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Found a PwDatabase! " nocase ascii wide
                        $string2 = /\/KeeTheft\.exe/ nocase ascii wide
                        $string3 = /\\KeeTheft\.exe/ nocase ascii wide
                        $string4 = ">KeeTheft<" nocase ascii wide

    condition:
        any of them
}