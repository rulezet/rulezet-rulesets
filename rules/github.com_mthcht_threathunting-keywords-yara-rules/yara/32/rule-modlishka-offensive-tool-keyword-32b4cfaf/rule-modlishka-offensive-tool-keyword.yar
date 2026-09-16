rule rule_Modlishka__offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Modlishka ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Modlishka "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Modlishka__offensive_tool_keyword = /\s\-config\smodlishka\.json\s/ nocase ascii wide
                        $string2_Modlishka__offensive_tool_keyword = /\/Modlishka\.git/ nocase ascii wide
                        $string3_Modlishka__offensive_tool_keyword = "drk1wi/Modlishka" nocase ascii wide
                        $string4_Modlishka__offensive_tool_keyword = "Modlishka/config" nocase ascii wide
                        $string5_Modlishka__offensive_tool_keyword = "MODLISHKA_BIN" nocase ascii wide
                        $string6_Modlishka__offensive_tool_keyword = "Modlishka-linux-amd64"
                        $string7_Modlishka__offensive_tool_keyword = /Modlishka\-windows\-.{0,1000}\-amd64\.exe/ nocase ascii wide
                        $string8_Modlishka__offensive_tool_keyword = "proxy_linux_amd64"

    condition:
        any of them
}