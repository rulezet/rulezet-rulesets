rule rule_DirtyCLR_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DirtyCLR' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirtyCLR"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DirtyCLR_offensive_tool_keyword = /\/DirtyCLR\.git/ nocase ascii wide
                        $string2_DirtyCLR_offensive_tool_keyword = /\\DirtyCLR\.sln/ nocase ascii wide
                        $string3_DirtyCLR_offensive_tool_keyword = /\\DirtyCLR\-main/ nocase ascii wide
                        $string4_DirtyCLR_offensive_tool_keyword = ">DirtyCLR<" nocase ascii wide
                        $string5_DirtyCLR_offensive_tool_keyword = "46EB7B83-3404-4DFC-94CC-704B02D11464" nocase ascii wide
                        $string6_DirtyCLR_offensive_tool_keyword = "827310760fa3d7371a22ff5f06e406f3e0a6cbe1c7e7f38244e0334a2d5eca7d" nocase ascii wide
                        $string7_DirtyCLR_offensive_tool_keyword = "8e2f8144fae305ecff5759bb38e384682642e766dfe85179555d7b621d92b836" nocase ascii wide
                        $string8_DirtyCLR_offensive_tool_keyword = "dirtyclrdomain" nocase ascii wide
                        $string9_DirtyCLR_offensive_tool_keyword = "ipSlav/DirtyCLR" nocase ascii wide
                        $string10_DirtyCLR_offensive_tool_keyword = /key.{0,1000}kda47y298uned/ nocase ascii wide
                        $string11_DirtyCLR_offensive_tool_keyword = /sn\.exe\s\-k\skey\.snk/ nocase ascii wide

    condition:
        any of them
}