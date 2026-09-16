rule rule_Zloader_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Zloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Zloader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Zloader_offensive_tool_keyword = /\sflash\.bat/ nocase ascii wide
                        $string2_Zloader_offensive_tool_keyword = /cmd\.exe\s\/c\szoom1\.msi/ nocase ascii wide
                        $string3_Zloader_offensive_tool_keyword = /flashupdate\.ps1/ nocase ascii wide
                        $string4_Zloader_offensive_tool_keyword = /powershell\sInvoke\-WebRequest\shttp.{0,1000}\.bat\s/ nocase ascii wide
                        $string5_Zloader_offensive_tool_keyword = "Zloader-FCVP" nocase ascii wide
                        $string6_Zloader_offensive_tool_keyword = /zoom1\.msi\.gpg/ nocase ascii wide
                        $string7_Zloader_offensive_tool_keyword = /zoom2\.dll\.gpg/ nocase ascii wide

    condition:
        any of them
}