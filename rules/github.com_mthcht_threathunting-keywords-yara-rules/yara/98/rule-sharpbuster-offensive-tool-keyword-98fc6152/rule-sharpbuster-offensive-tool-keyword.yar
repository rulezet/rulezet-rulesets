rule rule_SharpBuster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpBuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpBuster_offensive_tool_keyword = /\sSharpBuster\.dll/ nocase ascii wide
                        $string2_SharpBuster_offensive_tool_keyword = /\sSharpBuster\.exe/ nocase ascii wide
                        $string3_SharpBuster_offensive_tool_keyword = /\s\-u\shttp.{0,1000}\s\-\-wordlisturl\s.{0,1000}\s\-e\sphp\,aspx\s\-\-recursion\strue/ nocase ascii wide
                        $string4_SharpBuster_offensive_tool_keyword = /\/SharpBuster\.dll/ nocase ascii wide
                        $string5_SharpBuster_offensive_tool_keyword = /\/SharpBuster\.exe/ nocase ascii wide
                        $string6_SharpBuster_offensive_tool_keyword = /\\SharpBuster\.csproj/ nocase ascii wide
                        $string7_SharpBuster_offensive_tool_keyword = /\\SharpBuster\.dll/ nocase ascii wide
                        $string8_SharpBuster_offensive_tool_keyword = /\\SharpBuster\.exe/ nocase ascii wide
                        $string9_SharpBuster_offensive_tool_keyword = /\\SharpBuster\.pdb/ nocase ascii wide
                        $string10_SharpBuster_offensive_tool_keyword = /\\SharpBuster\.sln/ nocase ascii wide
                        $string11_SharpBuster_offensive_tool_keyword = "20ea253cc72883a4744a712d7dc06622b1655b70b4c32d2b74e4f2650919e2ec" nocase ascii wide
                        $string12_SharpBuster_offensive_tool_keyword = "33a6ca1dea55d7cd2edc7d25de16ce7689fcfc7c51fb2f26ebe1a07a3c81c017" nocase ascii wide
                        $string13_SharpBuster_offensive_tool_keyword = "3e475ed049ac5a398735ed67e51fc74e6da81238cb09f0bc1cf0e60d50c37f3d" nocase ascii wide
                        $string14_SharpBuster_offensive_tool_keyword = "62bba0a6ecfaf6e8052504a2699b1ba24822f2098223ba459f83a29ec4f70cf6" nocase ascii wide
                        $string15_SharpBuster_offensive_tool_keyword = "6412cb5d528ee93be2fc08b2c72cdee6c36e38ce5064d2685139bcbf9962298f" nocase ascii wide
                        $string16_SharpBuster_offensive_tool_keyword = "9786E418-6C4A-471D-97C0-8B5F2ED524C8" nocase ascii wide
                        $string17_SharpBuster_offensive_tool_keyword = "a32cdeddc7deb6d2ac210ec304930da4e9c6763975d72685fd7108ad48883715" nocase ascii wide
                        $string18_SharpBuster_offensive_tool_keyword = "cd8e9d2d24021e2a7ef20793d8b26f3c0baa8eea46e927875b53704761117bdd" nocase ascii wide
                        $string19_SharpBuster_offensive_tool_keyword = "cd8e9d2d24021e2a7ef20793d8b26f3c0baa8eea46e927875b53704761117bdd" nocase ascii wide
                        $string20_SharpBuster_offensive_tool_keyword = "f5cc1aeedb6a3e4a927ba5c1029c6075b2b9be7cf517cfdd8277bb0b00b5a60e" nocase ascii wide
                        $string21_SharpBuster_offensive_tool_keyword = /SharpBuster\.AssemblyInfo\.cs/ nocase ascii wide

    condition:
        any of them
}