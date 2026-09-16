rule pac2
{
    meta:
        description = "Detection patterns for the tool 'pac2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pac2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/c2_access\.log/
                        $string2 = /\/dummy\.pac2\.localhost/ nocase ascii wide
                        $string3 = "/mount/dropbox/Dropbox/pac2" nocase ascii wide
                        $string4 = "<h1>PowerAutomate C2 Portal" nocase ascii wide
                        $string5 = "77d2aa31773df8903d877f30db405b48896581f762b0d70e73e2c1014ea7b378" nocase ascii wide
                        $string6 = "a40ff8a806b8b2c385cd85e3c9627b09fca054a23fe7168aed459098266cab42" nocase ascii wide
                        $string7 = /from\s\.auth\simport\sPac2User/ nocase ascii wide
                        $string8 = /from\s\.dropbox\simport\sDropboxBeacon/ nocase ascii wide
                        $string9 = "hello_from_powerautomatec2" nocase ascii wide
                        $string10 = "http://localhost:9999/portal" nocase ascii wide
                        $string11 = "NTT-Security-Japan/pac2" nocase ascii wide
                        $string12 = /pac2\.localhost\:9999/ nocase ascii wide

    condition:
        any of them
}