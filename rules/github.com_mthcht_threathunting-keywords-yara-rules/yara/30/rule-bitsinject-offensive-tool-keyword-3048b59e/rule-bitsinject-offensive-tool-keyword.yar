rule rule_BITSInject_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BITSInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BITSInject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BITSInject_offensive_tool_keyword = /\sBITSInject\.py/ nocase ascii wide
                        $string2_BITSInject_offensive_tool_keyword = /\sBITSJobPayloads\.py/ nocase ascii wide
                        $string3_BITSInject_offensive_tool_keyword = /\/BITSInject\.git/ nocase ascii wide
                        $string4_BITSInject_offensive_tool_keyword = /\/BITSInject\.py/ nocase ascii wide
                        $string5_BITSInject_offensive_tool_keyword = /\/BITSJobPayloads\.py/ nocase ascii wide
                        $string6_BITSInject_offensive_tool_keyword = /\\BITSInject\.py/ nocase ascii wide
                        $string7_BITSInject_offensive_tool_keyword = /\\BITSInject\-master/ nocase ascii wide
                        $string8_BITSInject_offensive_tool_keyword = /\\BITSJobPayloads\.py/ nocase ascii wide
                        $string9_BITSInject_offensive_tool_keyword = "09e0c32321b7bc4b6d95f4a36d9030ce2333d67ffff15e4ff51631c3c4aa319d" nocase ascii wide
                        $string10_BITSInject_offensive_tool_keyword = "880b020391f6702f07775929110ac0f9aff0cec6fce2bd8e1e079bcace792e33" nocase ascii wide
                        $string11_BITSInject_offensive_tool_keyword = "93362035A00C104A84F3B17E7B499CD700000000020000000000000000000000C00A1281B535EF499" nocase ascii wide
                        $string12_BITSInject_offensive_tool_keyword = "SafeBreach-Labs/BITSInject" nocase ascii wide

    condition:
        any of them
}