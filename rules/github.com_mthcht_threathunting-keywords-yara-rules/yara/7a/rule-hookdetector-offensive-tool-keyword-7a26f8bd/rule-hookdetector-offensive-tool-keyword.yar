rule rule_HookDetector_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HookDetector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HookDetector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HookDetector_offensive_tool_keyword = /\s0x.{0,1000}\s\-\sHOOK\sDETECTED/ nocase ascii wide
                        $string2_HookDetector_offensive_tool_keyword = /\/HookDetector\.exe/ nocase ascii wide
                        $string3_HookDetector_offensive_tool_keyword = /\\HookDetector\.csproj/ nocase ascii wide
                        $string4_HookDetector_offensive_tool_keyword = /\\HookDetector\.exe/ nocase ascii wide
                        $string5_HookDetector_offensive_tool_keyword = "master/HookDetector" nocase ascii wide

    condition:
        any of them
}