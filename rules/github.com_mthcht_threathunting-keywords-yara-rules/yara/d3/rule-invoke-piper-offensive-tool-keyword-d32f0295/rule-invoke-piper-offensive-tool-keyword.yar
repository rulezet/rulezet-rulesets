rule rule_invoke_piper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'invoke-piper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "invoke-piper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_invoke_piper_offensive_tool_keyword = /\s\-bindPipe\s.{0,1000}\s\-destHost\s.{0,1000}\s\-destPort\s/ nocase ascii wide
                        $string2_invoke_piper_offensive_tool_keyword = /\s\-remote\s\-bindPipe\s.{0,1000}\s\-bindPort\s.{0,1000}\s\-security/ nocase ascii wide
                        $string3_invoke_piper_offensive_tool_keyword = /\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-bindPort\s/ nocase ascii wide
                        $string4_invoke_piper_offensive_tool_keyword = "Invoke-Piper" nocase ascii wide
                        $string5_invoke_piper_offensive_tool_keyword = "Invoke-PiperClient" nocase ascii wide
                        $string6_invoke_piper_offensive_tool_keyword = "Invoke-PiperServer" nocase ascii wide
                        $string7_invoke_piper_offensive_tool_keyword = /\-remote\s\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-destHost\s/ nocase ascii wide

    condition:
        any of them
}