rule rule_pac2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pac2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pac2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pac2_offensive_tool_keyword = /\/c2_access\.log/
                        $string2_pac2_offensive_tool_keyword = /\/dummy\.pac2\.localhost/ nocase ascii wide
                        $string3_pac2_offensive_tool_keyword = "/mount/dropbox/Dropbox/pac2" nocase ascii wide
                        $string4_pac2_offensive_tool_keyword = "<h1>PowerAutomate C2 Portal" nocase ascii wide
                        $string5_pac2_offensive_tool_keyword = "77d2aa31773df8903d877f30db405b48896581f762b0d70e73e2c1014ea7b378" nocase ascii wide
                        $string6_pac2_offensive_tool_keyword = "a40ff8a806b8b2c385cd85e3c9627b09fca054a23fe7168aed459098266cab42" nocase ascii wide
                        $string7_pac2_offensive_tool_keyword = /from\s\.auth\simport\sPac2User/ nocase ascii wide
                        $string8_pac2_offensive_tool_keyword = /from\s\.dropbox\simport\sDropboxBeacon/ nocase ascii wide
                        $string9_pac2_offensive_tool_keyword = "hello_from_powerautomatec2" nocase ascii wide
                        $string10_pac2_offensive_tool_keyword = "http://localhost:9999/portal" nocase ascii wide
                        $string11_pac2_offensive_tool_keyword = "NTT-Security-Japan/pac2" nocase ascii wide
                        $string12_pac2_offensive_tool_keyword = /pac2\.localhost\:9999/ nocase ascii wide

    condition:
        any of them
}