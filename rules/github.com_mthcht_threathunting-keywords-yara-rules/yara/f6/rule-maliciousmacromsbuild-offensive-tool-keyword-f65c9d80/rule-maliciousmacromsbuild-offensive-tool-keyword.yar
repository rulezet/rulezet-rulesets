rule rule_MaliciousMacroMSBuild_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MaliciousMacroMSBuild' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MaliciousMacroMSBuild"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MaliciousMacroMSBuild_offensive_tool_keyword = /\sm3\-gen\.py\s/ nocase ascii wide
                        $string2_MaliciousMacroMSBuild_offensive_tool_keyword = /\s\-p\spowershell\s\-i\s.{0,1000}\.ps1\s\-o\s.{0,1000}\.vba/ nocase ascii wide
                        $string3_MaliciousMacroMSBuild_offensive_tool_keyword = /\s\-p\sshellcode\s\-i\s.{0,1000}\.bin\s\-o\s.{0,1000}\.vba/ nocase ascii wide
                        $string4_MaliciousMacroMSBuild_offensive_tool_keyword = /\/m3\-gen\.py\s/
                        $string5_MaliciousMacroMSBuild_offensive_tool_keyword = "/MaliciousMacroMSBuild" nocase ascii wide
                        $string6_MaliciousMacroMSBuild_offensive_tool_keyword = /\\m3\-gen\.py/ nocase ascii wide
                        $string7_MaliciousMacroMSBuild_offensive_tool_keyword = "MaliciousMacroMSBuild-master" nocase ascii wide

    condition:
        any of them
}