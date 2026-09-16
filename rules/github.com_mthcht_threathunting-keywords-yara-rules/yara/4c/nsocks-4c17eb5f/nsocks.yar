rule nsocks
{
    meta:
        description = "Detection patterns for the tool 'nsocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nsocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/nsocks\.dll/ nocase ascii wide
                        $string2 = /\/NSocks\.exe/ nocase ascii wide
                        $string3 = /\/NSocks\.git/ nocase ascii wide
                        $string4 = /\\nsocks\.dll/ nocase ascii wide
                        $string5 = /\\nsocks\.exe/ nocase ascii wide
                        $string6 = /\>Nsocks\.dll\</ nocase ascii wide
                        $string7 = ">Nsocks<" nocase ascii wide
                        $string8 = "2e777ea84aa3cca0a17f3a08776d0bb993ad0ca42b2276429f13e7e036d51746" nocase ascii wide
                        $string9 = "889E3D8B-58FA-462D-A2D8-3CB430484B6A" nocase ascii wide
                        $string10 = "bbepis/Nsocks" nocase ascii wide
                        $string11 = "CE5C7EF9-E890-48E5-8551-3E8F96DCB38F" nocase ascii wide
                        $string12 = "f283690950663e8831078bd3f7d02835047997f65445f90a364626fb835809c4" nocase ascii wide
                        $string13 = /https\:\/\/nsocks\.net\// nocase ascii wide
                        $string14 = /https\:\/\/nsocks\.net\/proxy/ nocase ascii wide
                        $string15 = /https\:\/\/nsocks4pvtcewb2ora3zk47ksx7dvazbxyhzp4myhegpthgkphpi7aad\.onion\// nocase ascii wide

    condition:
        any of them
}