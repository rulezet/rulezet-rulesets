rule rule_KrbRelay_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KrbRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KrbRelay_offensive_tool_keyword = /\sasktgt\s\/user\:\{0\}\s\/certificate\:\{1\}\s\/password\:\\"\{2\}\\"\s/ nocase ascii wide
                        $string2_KrbRelay_offensive_tool_keyword = /\s\-spn\scifs.{0,1000}\s\-session\s.{0,1000}\s\-clsid\s.{0,1000}\s\-secrets/ nocase ascii wide
                        $string3_KrbRelay_offensive_tool_keyword = /\/CheckPort\.exe/ nocase ascii wide
                        $string4_KrbRelay_offensive_tool_keyword = "/KrbRelay" nocase ascii wide
                        $string5_KrbRelay_offensive_tool_keyword = /\/KrbRelay\.exe/ nocase ascii wide
                        $string6_KrbRelay_offensive_tool_keyword = /\\KrbRelay\.exe/ nocase ascii wide
                        $string7_KrbRelay_offensive_tool_keyword = ">KrbRelay<" nocase ascii wide
                        $string8_KrbRelay_offensive_tool_keyword = /CheckPort\.csproj/ nocase ascii wide
                        $string9_KrbRelay_offensive_tool_keyword = "KrbRelay by @Cube0x0" nocase ascii wide
                        $string10_KrbRelay_offensive_tool_keyword = /KrbRelay.{0,1000}misc/ nocase ascii wide
                        $string11_KrbRelay_offensive_tool_keyword = /KrbRelay.{0,1000}smb/ nocase ascii wide
                        $string12_KrbRelay_offensive_tool_keyword = /KrbRelay.{0,1000}spoofing/ nocase ascii wide
                        $string13_KrbRelay_offensive_tool_keyword = /KrbRelay\.csproj/ nocase ascii wide
                        $string14_KrbRelay_offensive_tool_keyword = /KrbRelay\.exe\s/ nocase ascii wide
                        $string15_KrbRelay_offensive_tool_keyword = /KrbRelay\.exe/ nocase ascii wide
                        $string16_KrbRelay_offensive_tool_keyword = /KrbRelay\.sln/ nocase ascii wide
                        $string17_KrbRelay_offensive_tool_keyword = /\-llmnr\s\-spn\s\'.{0,1000}cifs.{0,1000}\s\-secrets/ nocase ascii wide
                        $string18_KrbRelay_offensive_tool_keyword = /OleViewDotNet\.psd1/ nocase ascii wide
                        $string19_KrbRelay_offensive_tool_keyword = /\-spn\s.{0,1000}\s\-clsid\s.{0,1000}\s\-shadowcred/ nocase ascii wide

    condition:
        any of them
}