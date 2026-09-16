rule JumpSession_BOF
{
    meta:
        description = "Detection patterns for the tool 'JumpSession_BOF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JumpSession_BOF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sJumpSession\.x64\.o/ nocase ascii wide
                        $string2 = /\sJumpSession\.x86\.o/ nocase ascii wide
                        $string3 = /\/JumpSession\.cna/ nocase ascii wide
                        $string4 = /\/JumpSession_BOF\.git/ nocase ascii wide
                        $string5 = "JumpSession_BOF-main" nocase ascii wide
                        $string6 = "Octoberfest7/JumpSession_BOF" nocase ascii wide

    condition:
        any of them
}