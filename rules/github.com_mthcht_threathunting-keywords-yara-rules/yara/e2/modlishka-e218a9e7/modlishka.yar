rule Modlishka_
{
    meta:
        description = "Detection patterns for the tool 'Modlishka ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Modlishka "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-config\smodlishka\.json\s/ nocase ascii wide
                        $string2 = /\/Modlishka\.git/ nocase ascii wide
                        $string3 = "drk1wi/Modlishka" nocase ascii wide
                        $string4 = "Modlishka/config" nocase ascii wide
                        $string5 = "MODLISHKA_BIN" nocase ascii wide
                        $string6 = "Modlishka-linux-amd64"
                        $string7 = /Modlishka\-windows\-.{0,1000}\-amd64\.exe/ nocase ascii wide
                        $string8 = "proxy_linux_amd64"

    condition:
        any of them
}