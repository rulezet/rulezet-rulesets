rule BabelStrike
{
    meta:
        description = "Detection patterns for the tool 'BabelStrike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabelStrike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBabelStrike\.py/ nocase ascii wide
                        $string2 = /\/BabelStrike\.git/ nocase ascii wide
                        $string3 = /\/BabelStrike\.py/ nocase ascii wide
                        $string4 = /\\BabelStrike\.py/ nocase ascii wide
                        $string5 = /babelstrike\.py\s\-/ nocase ascii wide
                        $string6 = "BabelStrike-main" nocase ascii wide
                        $string7 = "t3l3machus/BabelStrike" nocase ascii wide

    condition:
        any of them
}