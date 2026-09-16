rule Telemetry
{
    meta:
        description = "Detection patterns for the tool 'Telemetry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Telemetry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Remotely download Trojan files to " nocase ascii wide
                        $string2 = /\/Telemetry\.git/ nocase ascii wide
                        $string3 = /\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\fun/ nocase ascii wide
                        $string4 = "2f00a05b-263d-4fcc-846b-da82bd684603" nocase ascii wide
                        $string5 = "58de3ab6935d1248e937e333e917586efb058e8b7d65ade38989543c806bd23e" nocase ascii wide
                        $string6 = "5f026c27-f8e6-4052-b231-8451c6a73838" nocase ascii wide
                        $string7 = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase ascii wide
                        $string8 = "6455d210924926d364ebf88ff053821ff2d603ea99b17d1dbb454a7d061992cc" nocase ascii wide
                        $string9 = "d7a308da069dcf3990f4cbfe57b8a1cc79c5f6b1259da795bba61592b8cf4b08" nocase ascii wide
                        $string10 = "Execute command without file backdoor" nocase ascii wide
                        $string11 = /https\:\/\/www\.trustedsec\.com\/blog\/abusing\-windows\-telemetry\-for\-persistence\// nocase ascii wide
                        $string12 = "Imanfeng/Telemetry" nocase ascii wide
                        $string13 = /TELEMETRY\.exe\sinstall\s/ nocase ascii wide
                        $string14 = /TELEMETRY\.exe\sinstall\s\/command\:/ nocase ascii wide
                        $string15 = /TELEMETRY\.exe\sinstall\s\/path\:/ nocase ascii wide
                        $string16 = /TELEMETRY\.exe\sinstall\s\/url\:/ nocase ascii wide

    condition:
        any of them
}