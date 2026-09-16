rule smc
{
    meta:
        description = "Detection patterns for the tool 'smc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "smc -disable -mem" nocase ascii wide
                        $string2 = "smc -disable -ntp" nocase ascii wide
                        $string3 = "smc -disable -wss" nocase ascii wide
                        $string4 = "smc -enable -gem" nocase ascii wide
                        $string5 = /smc\.exe\s\-disable\s\-mem/ nocase ascii wide
                        $string6 = /smc\.exe\s\-disable\s\-ntp/ nocase ascii wide
                        $string7 = /smc\.exe\s\-disable\s\-wss/ nocase ascii wide
                        $string8 = /smc\.exe\s\-enable\s\-gem/ nocase ascii wide

    condition:
        any of them
}