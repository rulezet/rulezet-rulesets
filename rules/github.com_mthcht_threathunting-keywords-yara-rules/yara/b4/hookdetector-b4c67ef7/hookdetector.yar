rule HookDetector
{
    meta:
        description = "Detection patterns for the tool 'HookDetector' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HookDetector"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s0x.{0,1000}\s\-\sHOOK\sDETECTED/ nocase ascii wide
                        $string2 = /\/HookDetector\.exe/ nocase ascii wide
                        $string3 = /\\HookDetector\.csproj/ nocase ascii wide
                        $string4 = /\\HookDetector\.exe/ nocase ascii wide
                        $string5 = "master/HookDetector" nocase ascii wide

    condition:
        any of them
}