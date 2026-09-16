rule rule_ShadowForgeC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShadowForgeC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowForgeC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShadowForgeC2_offensive_tool_keyword = "/ShadowForgeC2" nocase ascii wide
                        $string2_ShadowForgeC2_offensive_tool_keyword = /cmd_powershell\.cpp/ nocase ascii wide
                        $string3_ShadowForgeC2_offensive_tool_keyword = /dist\/shadow\.exe/ nocase ascii wide
                        $string4_ShadowForgeC2_offensive_tool_keyword = /dist\\shadow\.exe/ nocase ascii wide
                        $string5_ShadowForgeC2_offensive_tool_keyword = "generate exe Shadow" nocase ascii wide
                        $string6_ShadowForgeC2_offensive_tool_keyword = "import ShadowForgeHome" nocase ascii wide
                        $string7_ShadowForgeC2_offensive_tool_keyword = /ShadowForge\.py/ nocase ascii wide
                        $string8_ShadowForgeC2_offensive_tool_keyword = "ShadowForgeC2-main" nocase ascii wide
                        $string9_ShadowForgeC2_offensive_tool_keyword = "shell whoami /user" nocase ascii wide
                        $string10_ShadowForgeC2_offensive_tool_keyword = /teamServer.{0,1000}ZoomAPI\.py/ nocase ascii wide

    condition:
        any of them
}