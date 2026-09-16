rule rule_ShadowHound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShadowHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShadowHound_offensive_tool_keyword = /\sbofhound\.py/ nocase ascii wide
                        $string2_ShadowHound_offensive_tool_keyword = /\/bofhound\.py/ nocase ascii wide
                        $string3_ShadowHound_offensive_tool_keyword = /\/ShadowHound\.git/ nocase ascii wide
                        $string4_ShadowHound_offensive_tool_keyword = /\\bofhound\.py/ nocase ascii wide
                        $string5_ShadowHound_offensive_tool_keyword = "a510e14853234b49b9053a18264aa29e4dfbf467edae47afe13a08d57d34dad4" nocase ascii wide
                        $string6_ShadowHound_offensive_tool_keyword = /Author\:\sYehuda\sSmirnov\s\(X\:\s\@yudasm_\sBlueSky\:\s\@yudasm\.bsky\.social\)/ nocase ascii wide
                        $string7_ShadowHound_offensive_tool_keyword = "b7ae4b58d31453da02817000dd7465ab68434f43e22d2b7a5ffc73f3fa65f6cd" nocase ascii wide
                        $string8_ShadowHound_offensive_tool_keyword = "Friends-Security/ShadowHound" nocase ascii wide
                        $string9_ShadowHound_offensive_tool_keyword = "shadowhound -Command " nocase ascii wide
                        $string10_ShadowHound_offensive_tool_keyword = "ShadowHound-ADM " nocase ascii wide
                        $string11_ShadowHound_offensive_tool_keyword = /ShadowHound\-ADM\.ps1/ nocase ascii wide
                        $string12_ShadowHound_offensive_tool_keyword = "ShadowHound-DS " nocase ascii wide
                        $string13_ShadowHound_offensive_tool_keyword = /ShadowHound\-DS\(/ nocase ascii wide
                        $string14_ShadowHound_offensive_tool_keyword = /ShadowHound\-DS\.ps1/ nocase ascii wide

    condition:
        any of them
}