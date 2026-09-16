rule onionpipe
{
    meta:
        description = "Detection patterns for the tool 'onionpipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onionpipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
                        $string2 = /\.onion\:31337/ nocase ascii wide
                        $string3 = /\.onion\:8000/ nocase ascii wide
                        $string4 = /\.onion\:81/ nocase ascii wide
                        $string5 = /\/onionpipe\.git/ nocase ascii wide
                        $string6 = "/onionpipe/releases/latest" nocase ascii wide
                        $string7 = "/onionpipe:main"
                        $string8 = "/usr/share/keyrings/tor-archive-keyring"
                        $string9 = /build_onionpipe\.bash/
                        $string10 = /build_tor_darwin\.bash/
                        $string11 = /build_tor_debian\.bash/
                        $string12 = "cmars/onionpipe" nocase ascii wide
                        $string13 = /dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did\.onion/ nocase ascii wide
                        $string14 = "failed to shut down Tor -- possible bug in bine" nocase ascii wide
                        $string15 = "make onionpipe" nocase ascii wide
                        $string16 = "onionpipe --" nocase ascii wide
                        $string17 = /onionpipe\s.{0,1000}\.onion\:/ nocase ascii wide
                        $string18 = /onionpipe\s.{0,1000}\:.{0,1000}\~/ nocase ascii wide
                        $string19 = "onionpipe /run/" nocase ascii wide
                        $string20 = "onionpipe 8000" nocase ascii wide
                        $string21 = "onionpipe client new " nocase ascii wide
                        $string22 = "onionpipe/secrets" nocase ascii wide
                        $string23 = "onionpipe/tor" nocase ascii wide
                        $string24 = "onionpipe-darwin-amd64-static"
                        $string25 = "onionpipe-linux-amd64-static"
                        $string26 = /sd6aq2r6jvuoeisrudq7jbqufjh6nck5buuzjmgalicgwrobgfj4lkqd\.onion/ nocase ascii wide

    condition:
        any of them
}