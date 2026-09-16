rule rule_onionpipe_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'onionpipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onionpipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_onionpipe_offensive_tool_keyword = /\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
                        $string2_onionpipe_offensive_tool_keyword = /\.onion\:31337/ nocase ascii wide
                        $string3_onionpipe_offensive_tool_keyword = /\.onion\:8000/ nocase ascii wide
                        $string4_onionpipe_offensive_tool_keyword = /\.onion\:81/ nocase ascii wide
                        $string5_onionpipe_offensive_tool_keyword = /\/onionpipe\.git/ nocase ascii wide
                        $string6_onionpipe_offensive_tool_keyword = "/onionpipe/releases/latest" nocase ascii wide
                        $string7_onionpipe_offensive_tool_keyword = "/onionpipe:main"
                        $string8_onionpipe_offensive_tool_keyword = "/usr/share/keyrings/tor-archive-keyring"
                        $string9_onionpipe_offensive_tool_keyword = /build_onionpipe\.bash/
                        $string10_onionpipe_offensive_tool_keyword = /build_tor_darwin\.bash/
                        $string11_onionpipe_offensive_tool_keyword = /build_tor_debian\.bash/
                        $string12_onionpipe_offensive_tool_keyword = "cmars/onionpipe" nocase ascii wide
                        $string13_onionpipe_offensive_tool_keyword = /dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did\.onion/ nocase ascii wide
                        $string14_onionpipe_offensive_tool_keyword = "failed to shut down Tor -- possible bug in bine" nocase ascii wide
                        $string15_onionpipe_offensive_tool_keyword = "make onionpipe" nocase ascii wide
                        $string16_onionpipe_offensive_tool_keyword = "onionpipe --" nocase ascii wide
                        $string17_onionpipe_offensive_tool_keyword = /onionpipe\s.{0,1000}\.onion\:/ nocase ascii wide
                        $string18_onionpipe_offensive_tool_keyword = /onionpipe\s.{0,1000}\:.{0,1000}\~/ nocase ascii wide
                        $string19_onionpipe_offensive_tool_keyword = "onionpipe /run/" nocase ascii wide
                        $string20_onionpipe_offensive_tool_keyword = "onionpipe 8000" nocase ascii wide
                        $string21_onionpipe_offensive_tool_keyword = "onionpipe client new " nocase ascii wide
                        $string22_onionpipe_offensive_tool_keyword = "onionpipe/secrets" nocase ascii wide
                        $string23_onionpipe_offensive_tool_keyword = "onionpipe/tor" nocase ascii wide
                        $string24_onionpipe_offensive_tool_keyword = "onionpipe-darwin-amd64-static"
                        $string25_onionpipe_offensive_tool_keyword = "onionpipe-linux-amd64-static"
                        $string26_onionpipe_offensive_tool_keyword = /sd6aq2r6jvuoeisrudq7jbqufjh6nck5buuzjmgalicgwrobgfj4lkqd\.onion/ nocase ascii wide

    condition:
        any of them
}