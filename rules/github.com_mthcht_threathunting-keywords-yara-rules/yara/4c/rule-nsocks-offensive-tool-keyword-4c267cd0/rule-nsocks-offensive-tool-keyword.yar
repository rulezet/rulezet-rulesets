rule rule_nsocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nsocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nsocks_offensive_tool_keyword = /\/nsocks\.dll/ nocase ascii wide
                        $string2_nsocks_offensive_tool_keyword = /\/NSocks\.exe/ nocase ascii wide
                        $string3_nsocks_offensive_tool_keyword = /\/NSocks\.git/ nocase ascii wide
                        $string4_nsocks_offensive_tool_keyword = /\\nsocks\.dll/ nocase ascii wide
                        $string5_nsocks_offensive_tool_keyword = /\\nsocks\.exe/ nocase ascii wide
                        $string6_nsocks_offensive_tool_keyword = /\>Nsocks\.dll\</ nocase ascii wide
                        $string7_nsocks_offensive_tool_keyword = ">Nsocks<" nocase ascii wide
                        $string8_nsocks_offensive_tool_keyword = "2e777ea84aa3cca0a17f3a08776d0bb993ad0ca42b2276429f13e7e036d51746" nocase ascii wide
                        $string9_nsocks_offensive_tool_keyword = "889E3D8B-58FA-462D-A2D8-3CB430484B6A" nocase ascii wide
                        $string10_nsocks_offensive_tool_keyword = "bbepis/Nsocks" nocase ascii wide
                        $string11_nsocks_offensive_tool_keyword = "CE5C7EF9-E890-48E5-8551-3E8F96DCB38F" nocase ascii wide
                        $string12_nsocks_offensive_tool_keyword = "f283690950663e8831078bd3f7d02835047997f65445f90a364626fb835809c4" nocase ascii wide
                        $string13_nsocks_offensive_tool_keyword = /https\:\/\/nsocks\.net\// nocase ascii wide
                        $string14_nsocks_offensive_tool_keyword = /https\:\/\/nsocks\.net\/proxy/ nocase ascii wide
                        $string15_nsocks_offensive_tool_keyword = /https\:\/\/nsocks4pvtcewb2ora3zk47ksx7dvazbxyhzp4myhegpthgkphpi7aad\.onion\// nocase ascii wide

    condition:
        any of them
}