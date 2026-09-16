rule rule_kerberoast_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'kerberoast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kerberoast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_kerberoast_offensive_tool_keyword = /\.local\.kirbi/ nocase ascii wide
                        $string2_kerberoast_offensive_tool_keyword = "/nidem/kerberoast" nocase ascii wide
                        $string3_kerberoast_offensive_tool_keyword = "/xan7r/kerberoast" nocase ascii wide
                        $string4_kerberoast_offensive_tool_keyword = /autokerberoast\.ps1/ nocase ascii wide
                        $string5_kerberoast_offensive_tool_keyword = /autokerberoast_noMimikatz\.ps1/ nocase ascii wide
                        $string6_kerberoast_offensive_tool_keyword = /autoKirbi2hashcat\.py/ nocase ascii wide
                        $string7_kerberoast_offensive_tool_keyword = /autoTGS_NtlmCrack\.py/ nocase ascii wide
                        $string8_kerberoast_offensive_tool_keyword = /extracttgsrepfrompcap\.py/ nocase ascii wide
                        $string9_kerberoast_offensive_tool_keyword = /GetUserSPNs\.vbs/ nocase ascii wide
                        $string10_kerberoast_offensive_tool_keyword = "Invoke-AutoKerberoast" nocase ascii wide
                        $string11_kerberoast_offensive_tool_keyword = /kerberoast\.py/ nocase ascii wide
                        $string12_kerberoast_offensive_tool_keyword = /kerberos\:\:ptt\s.{0,1000}\.kirbi/ nocase ascii wide
                        $string13_kerberoast_offensive_tool_keyword = /kirbi2john\.py/ nocase ascii wide
                        $string14_kerberoast_offensive_tool_keyword = /krbroast\-pcap2hashcat\.py/ nocase ascii wide
                        $string15_kerberoast_offensive_tool_keyword = "setspn -A HTTP/" nocase ascii wide
                        $string16_kerberoast_offensive_tool_keyword = /setspn\s\-T\smedin\s\-Q\s.{0,1000}\// nocase ascii wide
                        $string17_kerberoast_offensive_tool_keyword = /setspn\.exe\s\-T\smedin\s\-Q\s.{0,1000}\// nocase ascii wide
                        $string18_kerberoast_offensive_tool_keyword = /tgsrepcrack\.py/ nocase ascii wide

    condition:
        any of them
}