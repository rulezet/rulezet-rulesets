rule rule_glit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'glit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "glit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_glit_offensive_tool_keyword = /\srepo\s\-u\shttps\:\/\/github\.com\// nocase ascii wide
                        $string2_glit_offensive_tool_keyword = /\/glit\.git/ nocase ascii wide
                        $string3_glit_offensive_tool_keyword = "/glit-cli"
                        $string4_glit_offensive_tool_keyword = "/glit-core"
                        $string5_glit_offensive_tool_keyword = /\\glit\.exe/ nocase ascii wide
                        $string6_glit_offensive_tool_keyword = /\\glit\-cli/ nocase ascii wide
                        $string7_glit_offensive_tool_keyword = "cargo install glit" nocase ascii wide
                        $string8_glit_offensive_tool_keyword = "glit org -" nocase ascii wide
                        $string9_glit_offensive_tool_keyword = "glit repo " nocase ascii wide
                        $string10_glit_offensive_tool_keyword = "glit user " nocase ascii wide
                        $string11_glit_offensive_tool_keyword = /glit\.exe\sorg/ nocase ascii wide
                        $string12_glit_offensive_tool_keyword = /glit\.exe\srepo/ nocase ascii wide
                        $string13_glit_offensive_tool_keyword = /glit\.exe\suser/ nocase ascii wide
                        $string14_glit_offensive_tool_keyword = "glit-i686-pc-windows-msvc" nocase ascii wide
                        $string15_glit_offensive_tool_keyword = /glit\-main\.zip/ nocase ascii wide
                        $string16_glit_offensive_tool_keyword = "glit-x86_64-apple-darwin"
                        $string17_glit_offensive_tool_keyword = "glit-x86_64-pc-windows-msvc" nocase ascii wide
                        $string18_glit_offensive_tool_keyword = "glit-x86_64-unknown-linux-gnu"
                        $string19_glit_offensive_tool_keyword = "shadawck/glit" nocase ascii wide

    condition:
        any of them
}