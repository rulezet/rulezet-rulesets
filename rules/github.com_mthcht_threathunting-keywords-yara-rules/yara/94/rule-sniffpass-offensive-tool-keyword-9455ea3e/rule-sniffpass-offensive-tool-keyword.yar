rule rule_SniffPass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SniffPass_offensive_tool_keyword = /\/password_sniffer\.html/ nocase ascii wide
                        $string2_SniffPass_offensive_tool_keyword = "/sniffpass-x64" nocase ascii wide
                        $string3_SniffPass_offensive_tool_keyword = /\\SniffPass\.chm/ nocase ascii wide
                        $string4_SniffPass_offensive_tool_keyword = /\\SniffPass\.pdb/ nocase ascii wide
                        $string5_SniffPass_offensive_tool_keyword = /\\sniffpass\-x64/ nocase ascii wide
                        $string6_SniffPass_offensive_tool_keyword = ">Password Sniffer<" nocase ascii wide
                        $string7_SniffPass_offensive_tool_keyword = ">SniffPass<" nocase ascii wide
                        $string8_SniffPass_offensive_tool_keyword = "1df8e073ca89d026578464b0da9748194ef62c826dea4af9848ef23b3ddf1785" nocase ascii wide
                        $string9_SniffPass_offensive_tool_keyword = "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620" nocase ascii wide
                        $string10_SniffPass_offensive_tool_keyword = /http\:\/\/www\.nirsoft\.net\/password_test/ nocase ascii wide
                        $string11_SniffPass_offensive_tool_keyword = "PacketSnifferClass1" nocase ascii wide
                        $string12_SniffPass_offensive_tool_keyword = /SniffPass\.exe/ nocase ascii wide
                        $string13_SniffPass_offensive_tool_keyword = /sniffpass\-x64\.zip/ nocase ascii wide
                        $string14_SniffPass_offensive_tool_keyword = /Software\\NirSoft\\SniffPass/ nocase ascii wide

    condition:
        any of them
}