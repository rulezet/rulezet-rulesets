rule rule_EnableAllTokenPrivs_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EnableAllTokenPrivs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EnableAllTokenPrivs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EnableAllTokenPrivs_offensive_tool_keyword = /\sEnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string2_EnableAllTokenPrivs_offensive_tool_keyword = /\sEnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string3_EnableAllTokenPrivs_offensive_tool_keyword = /\s\-\-pid\s.{0,1000}\s\-\-disable\s\-\-privilege\sSeDebugPrivilege/ nocase ascii wide
                        $string4_EnableAllTokenPrivs_offensive_tool_keyword = /\/EnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string5_EnableAllTokenPrivs_offensive_tool_keyword = /\/EnableAllTokenPrivs\.git/ nocase ascii wide
                        $string6_EnableAllTokenPrivs_offensive_tool_keyword = /\/EnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string7_EnableAllTokenPrivs_offensive_tool_keyword = /\\EnableAllTokenPrivs\.cs/ nocase ascii wide
                        $string8_EnableAllTokenPrivs_offensive_tool_keyword = /\\EnableAllTokenPrivs\.exe/ nocase ascii wide
                        $string9_EnableAllTokenPrivs_offensive_tool_keyword = /\\EnableAllTokenPrivs\.ps1/ nocase ascii wide
                        $string10_EnableAllTokenPrivs_offensive_tool_keyword = "3C8AA457-3659-4CDD-A685-66F7ED10DC4F" nocase ascii wide
                        $string11_EnableAllTokenPrivs_offensive_tool_keyword = "b7d464d0d52a2c35760aa7cf90a90e1ea3513a8827b175aba5099a90dee416f9" nocase ascii wide
                        $string12_EnableAllTokenPrivs_offensive_tool_keyword = "d1d4d168eeedd0867537ba4cf5befd1ea7adab62843d21088e6c51e27dec34c5" nocase ascii wide
                        $string13_EnableAllTokenPrivs_offensive_tool_keyword = /EnableAllTokenPrivs\.exe\.log/ nocase ascii wide
                        $string14_EnableAllTokenPrivs_offensive_tool_keyword = /execute\-assembly\s\-c\sEnableAllTokenPrivs\.EnableAllTokenPrivs\s/ nocase ascii wide
                        $string15_EnableAllTokenPrivs_offensive_tool_keyword = "xvt-void/EnableAllTokenPrivs" nocase ascii wide

    condition:
        any of them
}