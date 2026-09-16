rule SharpShellPipe
{
    meta:
        description = "Detection patterns for the tool 'SharpShellPipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpShellPipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpShellPipe\.git/ nocase ascii wide
                        $string2 = /\\\\DCSC_stdInPipe/ nocase ascii wide
                        $string3 = /\\\\DCSC_stdOutPipe/ nocase ascii wide
                        $string4 = "43BB3C30-39D7-4B6B-972E-1E2B94D4D53A" nocase ascii wide
                        $string5 = "DarkCoderSc/SharpShellPipe" nocase ascii wide
                        $string6 = /SharpShellPipe\.exe/ nocase ascii wide
                        $string7 = /SharpShellPipe\.sln/ nocase ascii wide
                        $string8 = "SharpShellPipe-main" nocase ascii wide
                        $string9 = /Successfully\sconnected.{0,1000}\sspawning\sshell\?/ nocase ascii wide

    condition:
        any of them
}