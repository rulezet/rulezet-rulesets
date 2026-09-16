rule rule_Ask4Creds_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ask4Creds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ask4Creds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ask4Creds_offensive_tool_keyword = /\sAsk4Creds\.ps1/ nocase ascii wide
                        $string2_Ask4Creds_offensive_tool_keyword = /\/Ask4Creds\.git/ nocase ascii wide
                        $string3_Ask4Creds_offensive_tool_keyword = /\/Ask4Creds\.ps1/ nocase ascii wide
                        $string4_Ask4Creds_offensive_tool_keyword = /\\Ask4Creds\.ps1/ nocase ascii wide
                        $string5_Ask4Creds_offensive_tool_keyword = "d3924d3bf6f59335a1e5453d80eaaa7404cea2e342105c3e69ddfb943aeb29c6" nocase ascii wide
                        $string6_Ask4Creds_offensive_tool_keyword = "Leo4j/Ask4Creds" nocase ascii wide

    condition:
        any of them
}