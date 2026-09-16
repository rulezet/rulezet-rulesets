rule rule_SharpEventLog_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpEventLog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEventLog"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpEventLog_offensive_tool_keyword = /\/SharpEventLog\.exe/ nocase ascii wide
                        $string2_SharpEventLog_offensive_tool_keyword = /\/SharpEventLog\.git/ nocase ascii wide
                        $string3_SharpEventLog_offensive_tool_keyword = /\\SharpEventLog\.csproj/ nocase ascii wide
                        $string4_SharpEventLog_offensive_tool_keyword = /\\SharpEventLog\.exe/ nocase ascii wide
                        $string5_SharpEventLog_offensive_tool_keyword = /\\SharpEventLog\.pdb/ nocase ascii wide
                        $string6_SharpEventLog_offensive_tool_keyword = /\\SharpEventLog\.sln/ nocase ascii wide
                        $string7_SharpEventLog_offensive_tool_keyword = /\\SharpEventLog\-master/ nocase ascii wide
                        $string8_SharpEventLog_offensive_tool_keyword = ">SharpEventLog<" nocase ascii wide
                        $string9_SharpEventLog_offensive_tool_keyword = "20ee05dd8552f0e3600b0d597d202e6d9baf1c1f30029d8a4773bb172016ce42" nocase ascii wide
                        $string10_SharpEventLog_offensive_tool_keyword = "3bf281b68fa29aece79cd0126a3b4552720cefe1045dc974b82523e439a11694" nocase ascii wide
                        $string11_SharpEventLog_offensive_tool_keyword = "4CA05D5C-AF6B-4F45-81E0-788BAA8D11A2" nocase ascii wide
                        $string12_SharpEventLog_offensive_tool_keyword = "9f4885b3b55f370d05e9426ba900cfa8daaa785129d6d80e576d16e4d497f6c8" nocase ascii wide
                        $string13_SharpEventLog_offensive_tool_keyword = "bb91387aea9bb46572a1b0a0be195f8ca26f47c7e5dc42c04b5b8a614a686c31" nocase ascii wide
                        $string14_SharpEventLog_offensive_tool_keyword = "bb91387aea9bb46572a1b0a0be195f8ca26f47c7e5dc42c04b5b8a614a686c31" nocase ascii wide
                        $string15_SharpEventLog_offensive_tool_keyword = "uknowsec/SharpEventLog" nocase ascii wide

    condition:
        any of them
}