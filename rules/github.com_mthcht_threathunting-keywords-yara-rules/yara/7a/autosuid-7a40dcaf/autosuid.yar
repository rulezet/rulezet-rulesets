rule AutoSUID
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sAutoSUID\.sh/ nocase ascii wide
                        $string2 = /\spwn_php\.me/ nocase ascii wide
                        $string3 = /\spwn_python\.me/ nocase ascii wide
                        $string4 = /\.\/AutoSUID\.sh/
                        $string5 = /\/AutoSUID\.git/ nocase ascii wide
                        $string6 = /\/pwn_php\.me/
                        $string7 = /\/pwn_python\.me/
                        $string8 = /AutoSUID\-main\./ nocase ascii wide
                        $string9 = "aW1wb3J0IG9zOyBvcy5leGVjbCgiL2Jpbi9zaCIsICJzaCIsICItcCIp" nocase ascii wide
                        $string10 = "IvanGlinkin/AutoSUID" nocase ascii wide
                        $string11 = "PD9waHAKcGNudGxfZXhlYygnL2Jpbi9zaCcsIFsnLXAnXSk7Cj8" nocase ascii wide

    condition:
        any of them
}