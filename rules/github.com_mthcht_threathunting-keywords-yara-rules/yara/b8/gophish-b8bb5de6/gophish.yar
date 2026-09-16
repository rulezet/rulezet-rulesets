rule gophish
{
    meta:
        description = "Detection patterns for the tool 'gophish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gophish"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " evilginx" nocase ascii wide
                        $string2 = "/evilginx" nocase ascii wide
                        $string3 = /\/gophish\.db/ nocase ascii wide
                        $string4 = "/gophish/" nocase ascii wide
                        $string5 = "c121f7d62fa5ecd27c3aaae5737a3de8f2e4def0c182058b6dd824aa92351e9c" nocase ascii wide
                        $string6 = /evilfeed\.go/ nocase ascii wide
                        $string7 = "evilginx-linux"
                        $string8 = "evilgophish" nocase ascii wide
                        $string9 = /gophish.{0,1000}phish\.go/ nocase ascii wide
                        $string10 = /gophish\.go/ nocase ascii wide
                        $string11 = "gophish/gophish" nocase ascii wide
                        $string12 = "localhost:1337" nocase ascii wide
                        $string13 = "lures create " nocase ascii wide
                        $string14 = /phish_test\.go/ nocase ascii wide
                        $string15 = "phishlets " nocase ascii wide
                        $string16 = "sneaky_gophish" nocase ascii wide
                        $string17 = "X-Gophish-Contact" nocase ascii wide

    condition:
        any of them
}