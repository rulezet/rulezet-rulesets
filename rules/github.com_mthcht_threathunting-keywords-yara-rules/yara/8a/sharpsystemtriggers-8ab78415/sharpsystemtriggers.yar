rule SharpSystemTriggers
{
    meta:
        description = "Detection patterns for the tool 'SharpSystemTriggers' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSystemTriggers"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/SharpSpoolTrigger" nocase ascii wide
                        $string2 = "/SharpSystemTriggers" nocase ascii wide
                        $string3 = /Midl2Bytes\.exe/ nocase ascii wide
                        $string4 = /SharpDcomTrigger\.exe/ nocase ascii wide
                        $string5 = /SharpEfsTriggeEfs\.exe/ nocase ascii wide
                        $string6 = /SharpSpoolTrigger\.exe/ nocase ascii wide
                        $string7 = /SharpSystemTriggers\.git/ nocase ascii wide
                        $string8 = /SharpSystemTriggers\.sln/ nocase ascii wide
                        $string9 = "SharpSystemTriggers-main" nocase ascii wide

    condition:
        any of them
}