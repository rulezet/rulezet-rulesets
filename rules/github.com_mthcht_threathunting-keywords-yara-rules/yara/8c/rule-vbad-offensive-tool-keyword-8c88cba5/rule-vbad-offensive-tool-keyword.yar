rule rule_vbad_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vbad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vbad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_vbad_offensive_tool_keyword = " fake small keys before real ones\"" nocase ascii wide
                        $string2_vbad_offensive_tool_keyword = " will be obfuscated and integrated in created documents" nocase ascii wide
                        $string3_vbad_offensive_tool_keyword = /\/VBad\.git/ nocase ascii wide
                        $string4_vbad_offensive_tool_keyword = /\\VBad\.py/ nocase ascii wide
                        $string5_vbad_offensive_tool_keyword = "7af0afcd0f9db86c97a7357aaaedd26ab3746e828d5c0febdd063099d0d3fee9" nocase ascii wide
                        $string6_vbad_offensive_tool_keyword = "Pepitoh/VBad" nocase ascii wide
                        $string7_vbad_offensive_tool_keyword = "VBA Obfuscation Tools combined with an MS office document generator" nocase ascii wide
                        $string8_vbad_offensive_tool_keyword = /Vbad\/VBad\.py/ nocase ascii wide

    condition:
        any of them
}