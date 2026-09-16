rule rule_KeeThiefSyscalls_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KeeThiefSyscalls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeeThiefSyscalls"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KeeThiefSyscalls_offensive_tool_keyword = /\sKeeTheft\.exe/ nocase ascii wide
                        $string2_KeeThiefSyscalls_offensive_tool_keyword = /\/KeeThief\.git/ nocase ascii wide
                        $string3_KeeThiefSyscalls_offensive_tool_keyword = /\\KeeTheft\.exe/ nocase ascii wide
                        $string4_KeeThiefSyscalls_offensive_tool_keyword = "KeeTheft/Dinvoke" nocase ascii wide
                        $string5_KeeThiefSyscalls_offensive_tool_keyword = "KeeThiefSyscalls" nocase ascii wide

    condition:
        any of them
}