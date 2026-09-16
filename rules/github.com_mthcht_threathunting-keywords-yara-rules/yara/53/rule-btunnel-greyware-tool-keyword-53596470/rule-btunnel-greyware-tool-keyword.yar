rule rule_btunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'btunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "btunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_btunnel_greyware_tool_keyword = /\/\.btunnel\./
                        $string2_btunnel_greyware_tool_keyword = /\/btunnel\.exe/ nocase ascii wide
                        $string3_btunnel_greyware_tool_keyword = /\/btunnel\.log/
                        $string4_btunnel_greyware_tool_keyword = /\\\.btunnel\./ nocase ascii wide
                        $string5_btunnel_greyware_tool_keyword = /\\bored\-tunnel\-client/ nocase ascii wide
                        $string6_btunnel_greyware_tool_keyword = /\\btunnel\.exe/ nocase ascii wide
                        $string7_btunnel_greyware_tool_keyword = /\\btunnel\.log/ nocase ascii wide
                        $string8_btunnel_greyware_tool_keyword = "60e8a9e19b34ca6d9f1847504b7689b3f46b029ab07b4d13c6ccde026d78a0a4" nocase ascii wide
                        $string9_btunnel_greyware_tool_keyword = "af19236f06140b33ac3c78ae743627ba34dcd89be6d5c8dd22cac7f6eae19774" nocase ascii wide
                        $string10_btunnel_greyware_tool_keyword = /api\.btunnel\.in/ nocase ascii wide
                        $string11_btunnel_greyware_tool_keyword = /bored\-tunnel\-client_Windows_x86_64\./ nocase ascii wide
                        $string12_btunnel_greyware_tool_keyword = "btunnel domain " nocase ascii wide
                        $string13_btunnel_greyware_tool_keyword = "btunnel file " nocase ascii wide
                        $string14_btunnel_greyware_tool_keyword = "btunnel http" nocase ascii wide
                        $string15_btunnel_greyware_tool_keyword = "btunnel tcp --" nocase ascii wide
                        $string16_btunnel_greyware_tool_keyword = "btunnel tcp" nocase ascii wide
                        $string17_btunnel_greyware_tool_keyword = /btunnel\.exe\shttp/ nocase ascii wide
                        $string18_btunnel_greyware_tool_keyword = "eb1395952e6eb92d4f9a2babb56d29ef384d683387c6a990e79d5fe4ba86040f" nocase ascii wide
                        $string19_btunnel_greyware_tool_keyword = /http\:\/\/tcp\.btunnel\.in/ nocase ascii wide
                        $string20_btunnel_greyware_tool_keyword = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide
                        $string21_btunnel_greyware_tool_keyword = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide
                        $string22_btunnel_greyware_tool_keyword = /https\:\/\/www\.btunnel\.in\/downloads/ nocase ascii wide

    condition:
        any of them
}