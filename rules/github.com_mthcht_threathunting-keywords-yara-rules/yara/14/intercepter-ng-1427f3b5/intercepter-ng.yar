rule Intercepter_NG
{
    meta:
        description = "Detection patterns for the tool 'Intercepter-NG' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Intercepter-NG"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Intercepter\-NG.{0,1000}\.apk/ nocase ascii wide
                        $string2 = /http\:\/\/sniff\.su\/.{0,1000}\.gz/ nocase ascii wide
                        $string3 = /http\:\/\/sniff\.su\/.{0,1000}\.zip/ nocase ascii wide
                        $string4 = /https\:\/\/sniff\.su\/.{0,1000}\.gz/ nocase ascii wide
                        $string5 = /https\:\/\/sniff\.su\/.{0,1000}\.zip/ nocase ascii wide
                        $string6 = "Intercepter-NG" nocase ascii wide
                        $string7 = /Intercepter\-NG\-1\.0\.zip/ nocase ascii wide
                        $string8 = /Intercepter\-NG\-1\.3\.zip/ nocase ascii wide
                        $string9 = /sniff\.su\/Intercepter\-NG/ nocase ascii wide

    condition:
        any of them
}