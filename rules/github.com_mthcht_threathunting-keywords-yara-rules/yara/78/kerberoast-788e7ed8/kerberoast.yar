rule kerberoast
{
    meta:
        description = "Detection patterns for the tool 'kerberoast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kerberoast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.local\.kirbi/ nocase ascii wide
                        $string2 = "/nidem/kerberoast" nocase ascii wide
                        $string3 = "/xan7r/kerberoast" nocase ascii wide
                        $string4 = /autokerberoast\.ps1/ nocase ascii wide
                        $string5 = /autokerberoast_noMimikatz\.ps1/ nocase ascii wide
                        $string6 = /autoKirbi2hashcat\.py/ nocase ascii wide
                        $string7 = /autoTGS_NtlmCrack\.py/ nocase ascii wide
                        $string8 = /extracttgsrepfrompcap\.py/ nocase ascii wide
                        $string9 = /GetUserSPNs\.vbs/ nocase ascii wide
                        $string10 = "Invoke-AutoKerberoast" nocase ascii wide
                        $string11 = /kerberoast\.py/ nocase ascii wide
                        $string12 = /kerberos\:\:ptt\s.{0,1000}\.kirbi/ nocase ascii wide
                        $string13 = /kirbi2john\.py/ nocase ascii wide
                        $string14 = /krbroast\-pcap2hashcat\.py/ nocase ascii wide
                        $string15 = "setspn -A HTTP/" nocase ascii wide
                        $string16 = /setspn\s\-T\smedin\s\-Q\s.{0,1000}\// nocase ascii wide
                        $string17 = /setspn\.exe\s\-T\smedin\s\-Q\s.{0,1000}\// nocase ascii wide
                        $string18 = /tgsrepcrack\.py/ nocase ascii wide

    condition:
        any of them
}