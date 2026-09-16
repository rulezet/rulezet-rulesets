rule rule_expose_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'expose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expose"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_expose_greyware_tool_keyword = " /usr/local/bin/expose"
                        $string2_expose_greyware_tool_keyword = /\/expose\/database\/expose\.db/ nocase ascii wide
                        $string3_expose_greyware_tool_keyword = "/expose/raw/master/builds/expose" nocase ascii wide
                        $string4_expose_greyware_tool_keyword = "/src/expose serve "
                        $string5_expose_greyware_tool_keyword = "beyondcode/expose" nocase ascii wide
                        $string6_expose_greyware_tool_keyword = "docker build -t expose " nocase ascii wide
                        $string7_expose_greyware_tool_keyword = "docker run expose " nocase ascii wide
                        $string8_expose_greyware_tool_keyword = "expose share http://" nocase ascii wide
                        $string9_expose_greyware_tool_keyword = /exposeConfigPath\=\/src\/config\/expose\.php/ nocase ascii wide
                        $string10_expose_greyware_tool_keyword = /\'host\'\s\=\>\s\'sharedwithexpose\.com\'/ nocase ascii wide
                        $string11_expose_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:4040\/api\/logs\// nocase ascii wide
                        $string12_expose_greyware_tool_keyword = /https\:\/\/expose\.dev\/api\/servers/ nocase ascii wide
                        $string13_expose_greyware_tool_keyword = /https\:\/\/expose\.dev\/register/ nocase ascii wide

    condition:
        any of them
}