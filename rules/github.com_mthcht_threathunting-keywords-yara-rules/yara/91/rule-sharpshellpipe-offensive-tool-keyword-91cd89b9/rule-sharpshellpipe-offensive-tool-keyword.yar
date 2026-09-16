rule rule_SharpShellPipe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpShellPipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShellPipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpShellPipe_offensive_tool_keyword = /\/SharpShellPipe\.git/ nocase ascii wide
                        $string2_SharpShellPipe_offensive_tool_keyword = /\\\\DCSC_stdInPipe/ nocase ascii wide
                        $string3_SharpShellPipe_offensive_tool_keyword = /\\\\DCSC_stdOutPipe/ nocase ascii wide
                        $string4_SharpShellPipe_offensive_tool_keyword = "43BB3C30-39D7-4B6B-972E-1E2B94D4D53A" nocase ascii wide
                        $string5_SharpShellPipe_offensive_tool_keyword = "DarkCoderSc/SharpShellPipe" nocase ascii wide
                        $string6_SharpShellPipe_offensive_tool_keyword = /SharpShellPipe\.exe/ nocase ascii wide
                        $string7_SharpShellPipe_offensive_tool_keyword = /SharpShellPipe\.sln/ nocase ascii wide
                        $string8_SharpShellPipe_offensive_tool_keyword = "SharpShellPipe-main" nocase ascii wide
                        $string9_SharpShellPipe_offensive_tool_keyword = /Successfully\sconnected.{0,1000}\sspawning\sshell\?/ nocase ascii wide

    condition:
        any of them
}