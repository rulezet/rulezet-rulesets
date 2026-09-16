rule crossc2
{
    meta:
        description = "Detection patterns for the tool 'crossc2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crossc2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/CrossC2-test" nocase ascii wide
                        $string2 = "/mimipenguin/" nocase ascii wide
                        $string3 = /\/tmp\/c2\-rebind\.so/
                        $string4 = /c2profile\.profile/ nocase ascii wide
                        $string5 = "cc2_keystrokes" nocase ascii wide
                        $string6 = "cc2_portscan" nocase ascii wide
                        $string7 = /CCHOST\=127\.0\.0\.1.{0,1000}\/tmp\/c2/ nocase ascii wide
                        $string8 = "crossc2 dyn load" nocase ascii wide
                        $string9 = "CrossC2 framework" nocase ascii wide
                        $string10 = /CrossC2\.cna/ nocase ascii wide
                        $string11 = /CrossC2\.git/ nocase ascii wide
                        $string12 = /CrossC2\.Linux/
                        $string13 = /CrossC2\.MacOS/ nocase ascii wide
                        $string14 = /CrossC2\.Win/ nocase ascii wide
                        $string15 = "CrossC2_dev_" nocase ascii wide
                        $string16 = "CrossC2-cs" nocase ascii wide
                        $string17 = "CrossC2-GithubBot" nocase ascii wide
                        $string18 = "CrossC2Kit" nocase ascii wide
                        $string19 = "genCrossC2 " nocase ascii wide
                        $string20 = /genCrossC2\.Win\.exe/ nocase ascii wide
                        $string21 = "gloxec/CrossC2" nocase ascii wide
                        $string22 = /http\:\/\/127\.0\.0\.1\/CrossC2/ nocase ascii wide
                        $string23 = /http\:\/\/127\.0\.0\.1\:443\/aaaaaaaaa/ nocase ascii wide
                        $string24 = /http\:\/\/127\.0\.0\.1\:443\/bbbbbbbbb/ nocase ascii wide
                        $string25 = /mimipenguin\./ nocase ascii wide

    condition:
        any of them
}