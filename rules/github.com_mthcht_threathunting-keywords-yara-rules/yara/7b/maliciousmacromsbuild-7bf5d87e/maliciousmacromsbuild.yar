rule MaliciousMacroMSBuild
{
    meta:
        description = "Detection patterns for the tool 'MaliciousMacroMSBuild' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaliciousMacroMSBuild"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sm3\-gen\.py\s/ nocase ascii wide
                        $string2 = /\s\-p\spowershell\s\-i\s.{0,1000}\.ps1\s\-o\s.{0,1000}\.vba/ nocase ascii wide
                        $string3 = /\s\-p\sshellcode\s\-i\s.{0,1000}\.bin\s\-o\s.{0,1000}\.vba/ nocase ascii wide
                        $string4 = /\/m3\-gen\.py\s/
                        $string5 = "/MaliciousMacroMSBuild" nocase ascii wide
                        $string6 = /\\m3\-gen\.py/ nocase ascii wide
                        $string7 = "MaliciousMacroMSBuild-master" nocase ascii wide

    condition:
        any of them
}