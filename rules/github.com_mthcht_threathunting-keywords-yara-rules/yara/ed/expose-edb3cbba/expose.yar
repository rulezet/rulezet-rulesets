rule expose
{
    meta:
        description = "Detection patterns for the tool 'expose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expose"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " /usr/local/bin/expose"
                        $string2 = /\/expose\/database\/expose\.db/ nocase ascii wide
                        $string3 = "/expose/raw/master/builds/expose" nocase ascii wide
                        $string4 = "/src/expose serve "
                        $string5 = "beyondcode/expose" nocase ascii wide
                        $string6 = "docker build -t expose " nocase ascii wide
                        $string7 = "docker run expose " nocase ascii wide
                        $string8 = "expose share http://" nocase ascii wide
                        $string9 = /exposeConfigPath\=\/src\/config\/expose\.php/ nocase ascii wide
                        $string10 = /\'host\'\s\=\>\s\'sharedwithexpose\.com\'/ nocase ascii wide
                        $string11 = /http\:\/\/127\.0\.0\.1\:4040\/api\/logs\// nocase ascii wide
                        $string12 = /https\:\/\/expose\.dev\/api\/servers/ nocase ascii wide
                        $string13 = /https\:\/\/expose\.dev\/register/ nocase ascii wide

    condition:
        any of them
}