rule Zloader
{
    meta:
        description = "Detection patterns for the tool 'Zloader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Zloader"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sflash\.bat/ nocase ascii wide
                        $string2 = /cmd\.exe\s\/c\szoom1\.msi/ nocase ascii wide
                        $string3 = /flashupdate\.ps1/ nocase ascii wide
                        $string4 = /powershell\sInvoke\-WebRequest\shttp.{0,1000}\.bat\s/ nocase ascii wide
                        $string5 = "Zloader-FCVP" nocase ascii wide
                        $string6 = /zoom1\.msi\.gpg/ nocase ascii wide
                        $string7 = /zoom2\.dll\.gpg/ nocase ascii wide

    condition:
        any of them
}