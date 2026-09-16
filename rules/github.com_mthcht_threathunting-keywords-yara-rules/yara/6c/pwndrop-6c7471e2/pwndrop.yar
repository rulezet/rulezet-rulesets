rule pwndrop
{
    meta:
        description = "Detection patterns for the tool 'pwndrop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwndrop"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/pwndrop\s/
                        $string2 = /\/pwndrop\.git/ nocase ascii wide
                        $string3 = /\/pwndrop\.ini/
                        $string4 = "/usr/local/pwndrop/"
                        $string5 = "kgretzky/pwndrop" nocase ascii wide
                        $string6 = "pwndrop install" nocase ascii wide
                        $string7 = "pwndrop start" nocase ascii wide
                        $string8 = "pwndrop status" nocase ascii wide
                        $string9 = "pwndrop stop" nocase ascii wide
                        $string10 = "pwndrop-linux-amd64"
                        $string11 = "pwndrop-master" nocase ascii wide

    condition:
        any of them
}