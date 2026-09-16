rule rule_SCMUACBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SCMUACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCMUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SCMUACBypass_offensive_tool_keyword = /\sscmuacbypass\.cpp/ nocase ascii wide
                        $string2_SCMUACBypass_offensive_tool_keyword = /\sscmuacbypass\.exe/ nocase ascii wide
                        $string3_SCMUACBypass_offensive_tool_keyword = /\/scmuacbypass\.cpp/ nocase ascii wide
                        $string4_SCMUACBypass_offensive_tool_keyword = /\/SCMUACBypass\.exe/ nocase ascii wide
                        $string5_SCMUACBypass_offensive_tool_keyword = /\/scmuacbypass\.exe/ nocase ascii wide
                        $string6_SCMUACBypass_offensive_tool_keyword = /\/SCMUACBypass\.git/ nocase ascii wide
                        $string7_SCMUACBypass_offensive_tool_keyword = "/SCMUACBypass/" nocase ascii wide
                        $string8_SCMUACBypass_offensive_tool_keyword = /\\scmuacbypass\.cpp/ nocase ascii wide
                        $string9_SCMUACBypass_offensive_tool_keyword = /\\scmuacbypass\.exe/ nocase ascii wide
                        $string10_SCMUACBypass_offensive_tool_keyword = /\\SCMUACBypass\.exe/ nocase ascii wide
                        $string11_SCMUACBypass_offensive_tool_keyword = /\\SCMUACBypass\\/ nocase ascii wide
                        $string12_SCMUACBypass_offensive_tool_keyword = /UACBypassedService\.exe/ nocase ascii wide

    condition:
        any of them
}