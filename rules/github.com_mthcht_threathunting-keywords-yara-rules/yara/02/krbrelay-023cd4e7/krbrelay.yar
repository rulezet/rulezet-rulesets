rule KrbRelay
{
    meta:
        description = "Detection patterns for the tool 'KrbRelay' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelay"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sasktgt\s\/user\:\{0\}\s\/certificate\:\{1\}\s\/password\:\\"\{2\}\\"\s/ nocase ascii wide
                        $string2 = /\s\-spn\scifs.{0,1000}\s\-session\s.{0,1000}\s\-clsid\s.{0,1000}\s\-secrets/ nocase ascii wide
                        $string3 = /\/CheckPort\.exe/ nocase ascii wide
                        $string4 = "/KrbRelay" nocase ascii wide
                        $string5 = /\/KrbRelay\.exe/ nocase ascii wide
                        $string6 = /\\KrbRelay\.exe/ nocase ascii wide
                        $string7 = ">KrbRelay<" nocase ascii wide
                        $string8 = /CheckPort\.csproj/ nocase ascii wide
                        $string9 = "KrbRelay by @Cube0x0" nocase ascii wide
                        $string10 = /KrbRelay.{0,1000}misc/ nocase ascii wide
                        $string11 = /KrbRelay.{0,1000}smb/ nocase ascii wide
                        $string12 = /KrbRelay.{0,1000}spoofing/ nocase ascii wide
                        $string13 = /KrbRelay\.csproj/ nocase ascii wide
                        $string14 = /KrbRelay\.exe\s/ nocase ascii wide
                        $string15 = /KrbRelay\.exe/ nocase ascii wide
                        $string16 = /KrbRelay\.sln/ nocase ascii wide
                        $string17 = /\-llmnr\s\-spn\s\'.{0,1000}cifs.{0,1000}\s\-secrets/ nocase ascii wide
                        $string18 = /OleViewDotNet\.psd1/ nocase ascii wide
                        $string19 = /\-spn\s.{0,1000}\s\-clsid\s.{0,1000}\s\-shadowcred/ nocase ascii wide

    condition:
        any of them
}