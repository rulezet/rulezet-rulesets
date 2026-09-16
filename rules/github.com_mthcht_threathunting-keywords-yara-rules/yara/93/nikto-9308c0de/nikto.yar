rule nikto
{
    meta:
        description = "Detection patterns for the tool 'nikto' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nikto"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install nikto"
                        $string2 = /\snikto\.pl\s/
                        $string3 = /\/nikto\.git/
                        $string4 = /\/nikto\.pl/
                        $string5 = /\/nikto\.pl/
                        $string6 = "/sullo/nikto"
                        $string7 = "nikto -C all "
                        $string8 = "nikto/program"
                        $string9 = /perl\snikto\.pl\s\-h/
                        $string10 = /program\/replay\.pl/
                        $string11 = "sullo/nikto"
                        $string12 = "nikto -"

    condition:
        any of them
}