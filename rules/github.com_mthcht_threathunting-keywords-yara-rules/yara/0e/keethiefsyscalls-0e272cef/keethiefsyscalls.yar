rule KeeThiefSyscalls
{
    meta:
        description = "Detection patterns for the tool 'KeeThiefSyscalls' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeeThiefSyscalls"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sKeeTheft\.exe/ nocase ascii wide
                        $string2 = /\/KeeThief\.git/ nocase ascii wide
                        $string3 = /\\KeeTheft\.exe/ nocase ascii wide
                        $string4 = "KeeTheft/Dinvoke" nocase ascii wide
                        $string5 = "KeeThiefSyscalls" nocase ascii wide

    condition:
        any of them
}