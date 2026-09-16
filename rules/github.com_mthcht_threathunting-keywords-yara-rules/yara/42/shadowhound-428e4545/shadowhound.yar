rule ShadowHound
{
    meta:
        description = "Detection patterns for the tool 'ShadowHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbofhound\.py/ nocase ascii wide
                        $string2 = /\/bofhound\.py/ nocase ascii wide
                        $string3 = /\/ShadowHound\.git/ nocase ascii wide
                        $string4 = /\\bofhound\.py/ nocase ascii wide
                        $string5 = "a510e14853234b49b9053a18264aa29e4dfbf467edae47afe13a08d57d34dad4" nocase ascii wide
                        $string6 = /Author\:\sYehuda\sSmirnov\s\(X\:\s\@yudasm_\sBlueSky\:\s\@yudasm\.bsky\.social\)/ nocase ascii wide
                        $string7 = "b7ae4b58d31453da02817000dd7465ab68434f43e22d2b7a5ffc73f3fa65f6cd" nocase ascii wide
                        $string8 = "Friends-Security/ShadowHound" nocase ascii wide
                        $string9 = "shadowhound -Command " nocase ascii wide
                        $string10 = "ShadowHound-ADM " nocase ascii wide
                        $string11 = /ShadowHound\-ADM\.ps1/ nocase ascii wide
                        $string12 = "ShadowHound-DS " nocase ascii wide
                        $string13 = /ShadowHound\-DS\(/ nocase ascii wide
                        $string14 = /ShadowHound\-DS\.ps1/ nocase ascii wide

    condition:
        any of them
}