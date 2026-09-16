rule invoke_piper
{
    meta:
        description = "Detection patterns for the tool 'invoke-piper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "invoke-piper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-bindPipe\s.{0,1000}\s\-destHost\s.{0,1000}\s\-destPort\s/ nocase ascii wide
                        $string2 = /\s\-remote\s\-bindPipe\s.{0,1000}\s\-bindPort\s.{0,1000}\s\-security/ nocase ascii wide
                        $string3 = /\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-bindPort\s/ nocase ascii wide
                        $string4 = "Invoke-Piper" nocase ascii wide
                        $string5 = "Invoke-PiperClient" nocase ascii wide
                        $string6 = "Invoke-PiperServer" nocase ascii wide
                        $string7 = /\-remote\s\-destPipe\s.{0,1000}\s\-pipeHost\s.{0,1000}\s\-destHost\s/ nocase ascii wide

    condition:
        any of them
}