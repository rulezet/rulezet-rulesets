rule rule_JumpSession_BOF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'JumpSession_BOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JumpSession_BOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_JumpSession_BOF_offensive_tool_keyword = /\sJumpSession\.x64\.o/ nocase ascii wide
                        $string2_JumpSession_BOF_offensive_tool_keyword = /\sJumpSession\.x86\.o/ nocase ascii wide
                        $string3_JumpSession_BOF_offensive_tool_keyword = /\/JumpSession\.cna/ nocase ascii wide
                        $string4_JumpSession_BOF_offensive_tool_keyword = /\/JumpSession_BOF\.git/ nocase ascii wide
                        $string5_JumpSession_BOF_offensive_tool_keyword = "JumpSession_BOF-main" nocase ascii wide
                        $string6_JumpSession_BOF_offensive_tool_keyword = "Octoberfest7/JumpSession_BOF" nocase ascii wide

    condition:
        any of them
}