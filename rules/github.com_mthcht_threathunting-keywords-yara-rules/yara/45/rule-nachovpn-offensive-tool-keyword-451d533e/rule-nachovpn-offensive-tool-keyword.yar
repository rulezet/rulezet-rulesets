rule rule_NachoVPN_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NachoVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NachoVPN"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NachoVPN_offensive_tool_keyword = " localgroup administrators pwnd /add" nocase ascii wide
                        $string2_NachoVPN_offensive_tool_keyword = /\snachovpn\.server/ nocase ascii wide
                        $string3_NachoVPN_offensive_tool_keyword = " nachovpn:latest " nocase ascii wide
                        $string4_NachoVPN_offensive_tool_keyword = " --rm -it nachovpn" nocase ascii wide
                        $string5_NachoVPN_offensive_tool_keyword = " user pwnd Passw0rd123!" nocase ascii wide
                        $string6_NachoVPN_offensive_tool_keyword = /\/NachoVPN\.git/ nocase ascii wide
                        $string7_NachoVPN_offensive_tool_keyword = "/nachovpn:release" nocase ascii wide
                        $string8_NachoVPN_offensive_tool_keyword = /\/nachovpn\-1\.0\.0\-py3\-none\-any\.whl/ nocase ascii wide
                        $string9_NachoVPN_offensive_tool_keyword = "AmberWolfCyber/NachoVPN" nocase ascii wide
                        $string10_NachoVPN_offensive_tool_keyword = /connect\.nachovpn\.local/ nocase ascii wide
                        $string11_NachoVPN_offensive_tool_keyword = /nachovpn\.core\./ nocase ascii wide
                        $string12_NachoVPN_offensive_tool_keyword = /nachovpn\.local/ nocase ascii wide
                        $string13_NachoVPN_offensive_tool_keyword = /nachovpn\.plugins\./ nocase ascii wide
                        $string14_NachoVPN_offensive_tool_keyword = /nachovpn\/server\.py/ nocase ascii wide
                        $string15_NachoVPN_offensive_tool_keyword = "touch /tmp/pwnd"

    condition:
        any of them
}