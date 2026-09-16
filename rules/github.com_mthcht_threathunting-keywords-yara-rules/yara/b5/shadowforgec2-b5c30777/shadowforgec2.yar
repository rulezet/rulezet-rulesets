rule ShadowForgeC2
{
    meta:
        description = "Detection patterns for the tool 'ShadowForgeC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowForgeC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ShadowForgeC2" nocase ascii wide
                        $string2 = /cmd_powershell\.cpp/ nocase ascii wide
                        $string3 = /dist\/shadow\.exe/ nocase ascii wide
                        $string4 = /dist\\shadow\.exe/ nocase ascii wide
                        $string5 = "generate exe Shadow" nocase ascii wide
                        $string6 = "import ShadowForgeHome" nocase ascii wide
                        $string7 = /ShadowForge\.py/ nocase ascii wide
                        $string8 = "ShadowForgeC2-main" nocase ascii wide
                        $string9 = "shell whoami /user" nocase ascii wide
                        $string10 = /teamServer.{0,1000}ZoomAPI\.py/ nocase ascii wide

    condition:
        any of them
}