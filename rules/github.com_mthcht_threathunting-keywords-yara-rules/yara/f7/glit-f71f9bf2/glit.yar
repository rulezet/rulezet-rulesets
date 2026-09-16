rule glit
{
    meta:
        description = "Detection patterns for the tool 'glit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "glit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\srepo\s\-u\shttps\:\/\/github\.com\// nocase ascii wide
                        $string2 = /\/glit\.git/ nocase ascii wide
                        $string3 = "/glit-cli"
                        $string4 = "/glit-core"
                        $string5 = /\\glit\.exe/ nocase ascii wide
                        $string6 = /\\glit\-cli/ nocase ascii wide
                        $string7 = "cargo install glit" nocase ascii wide
                        $string8 = "glit org -" nocase ascii wide
                        $string9 = "glit repo " nocase ascii wide
                        $string10 = "glit user " nocase ascii wide
                        $string11 = /glit\.exe\sorg/ nocase ascii wide
                        $string12 = /glit\.exe\srepo/ nocase ascii wide
                        $string13 = /glit\.exe\suser/ nocase ascii wide
                        $string14 = "glit-i686-pc-windows-msvc" nocase ascii wide
                        $string15 = /glit\-main\.zip/ nocase ascii wide
                        $string16 = "glit-x86_64-apple-darwin"
                        $string17 = "glit-x86_64-pc-windows-msvc" nocase ascii wide
                        $string18 = "glit-x86_64-unknown-linux-gnu"
                        $string19 = "shadawck/glit" nocase ascii wide

    condition:
        any of them
}