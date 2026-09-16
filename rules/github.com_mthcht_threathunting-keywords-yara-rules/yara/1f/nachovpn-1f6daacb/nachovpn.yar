rule NachoVPN
{
    meta:
        description = "Detection patterns for the tool 'NachoVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NachoVPN"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " localgroup administrators pwnd /add" nocase ascii wide
                        $string2 = /\snachovpn\.server/ nocase ascii wide
                        $string3 = " nachovpn:latest " nocase ascii wide
                        $string4 = " --rm -it nachovpn" nocase ascii wide
                        $string5 = " user pwnd Passw0rd123!" nocase ascii wide
                        $string6 = /\/NachoVPN\.git/ nocase ascii wide
                        $string7 = "/nachovpn:release" nocase ascii wide
                        $string8 = /\/nachovpn\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
                        $string9 = "AmberWolfCyber/NachoVPN" nocase ascii wide
                        $string10 = /connect\.nachovpn\.local/ nocase ascii wide
                        $string11 = /nachovpn\.core\./ nocase ascii wide
                        $string12 = /nachovpn\.local/ nocase ascii wide
                        $string13 = /nachovpn\.plugins\./ nocase ascii wide
                        $string14 = /nachovpn\/server\.py/ nocase ascii wide
                        $string15 = "touch /tmp/pwnd"

    condition:
        any of them
}