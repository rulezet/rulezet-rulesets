rule rule_WLAN_Windows_Passwords_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WLAN-Windows-Passwords' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WLAN-Windows-Passwords"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WLAN_Windows_Passwords_offensive_tool_keyword = /\sWindows\-Passwords\.ps1/ nocase ascii wide
                        $string2_WLAN_Windows_Passwords_offensive_tool_keyword = /\/Windows\-Passwords\.ps1/ nocase ascii wide
                        $string3_WLAN_Windows_Passwords_offensive_tool_keyword = /\\Windows\-Passwords\.ps1/ nocase ascii wide
                        $string4_WLAN_Windows_Passwords_offensive_tool_keyword = /Invoke\-RestMethod\s\-ContentType\s\'Application\/Json\'\s\-Uri\s\$discord\s\-Method\sPost\s\-Body\s\(\$Body\s\|\sConvertTo\-Json\)/ nocase ascii wide
                        $string5_WLAN_Windows_Passwords_offensive_tool_keyword = /netsh\swlan\sshow\sprofile\s\$wlan\skey\=clear\s\|\sSelect\-String\s.{0,1000}\?\<\=Key\sContent\\s\+\:\\s/ nocase ascii wide
                        $string6_WLAN_Windows_Passwords_offensive_tool_keyword = "WLAN-Windows-Passwords-Discord-Exfiltration" nocase ascii wide

    condition:
        any of them
}