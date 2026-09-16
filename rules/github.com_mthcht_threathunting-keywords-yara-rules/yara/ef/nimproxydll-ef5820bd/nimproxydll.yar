rule nimproxydll
{
    meta:
        description = "Detection patterns for the tool 'nimproxydll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimproxydll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\screateproxydll\.sh/ nocase ascii wide
                        $string2 = /\/createproxydll\.sh/ nocase ascii wide
                        $string3 = /\/nimproxydll\.git/ nocase ascii wide
                        $string4 = "/nimproxydll/" nocase ascii wide
                        $string5 = /\\nimproxydll\\/ nocase ascii wide
                        $string6 = /\\nimproxydll\-main\\/ nocase ascii wide
                        $string7 = "17257046150e6cbdc59be7873210cc6e0399ba51a5da24114f3c147bdc4fdb4c" nocase ascii wide
                        $string8 = "ab1b755120b2d5fb3db73f363a0b44881bc8b5e9699e27b804c9806b78de3a1b" nocase ascii wide
                        $string9 = /app\/dllproxy\.nim/ nocase ascii wide
                        $string10 = "cyllective/nimproxydll" nocase ascii wide
                        $string11 = "make image && make proxydll" nocase ascii wide

    condition:
        any of them
}