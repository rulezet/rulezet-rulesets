rule EnableAllTokenPrivs
{
    meta:
        description = "Detection patterns for the tool 'EnableAllTokenPrivs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EnableAllTokenPrivs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sEnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string2 = /\sEnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string3 = /\s\-\-pid\s.{0,1000}\s\-\-disable\s\-\-privilege\sSeDebugPrivilege/ nocase ascii wide
                        $string4 = /\/EnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string5 = /\/EnableAllTokenPrivs\.git/ nocase ascii wide
                        $string6 = /\/EnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string7 = /\\EnableAllTokenPrivs\.cs/ nocase ascii wide
                        $string8 = /\\EnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string9 = /\\EnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string10 = "3C8AA457-3659-4CDD-A685-66F7ED10DC4F" nocase ascii wide
                        $string11 = "b7d464d0d52a2c35760aa7cf90a90e1ea3513a8827b175aba5099a90dee416f9" nocase ascii wide
                        $string12 = "d1d4d168eeedd0867537ba4cf5befd1ea7adab62843d21088e6c51e27dec34c5" nocase ascii wide
                        $string13 = /EnableAllTokenPrivs\.exe\.log/ nocase ascii wide
                        $string14 = /execute\-assembly\s\-c\sEnableAllTokenPrivs\.EnableAllTokenPrivs\s/ nocase ascii wide
                        $string15 = "xvt-void/EnableAllTokenPrivs" nocase ascii wide

    condition:
        any of them
}