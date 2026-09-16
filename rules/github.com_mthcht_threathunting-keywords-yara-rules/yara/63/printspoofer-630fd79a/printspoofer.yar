rule PrintSpoofer
{
    meta:
        description = "Detection patterns for the tool 'PrintSpoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/PrintSpoofer\.exe/ nocase ascii wide
                        $string2 = /\/PrintSpoofer\.git/ nocase ascii wide
                        $string3 = /\\PrintSpoofer\.exe/ nocase ascii wide
                        $string4 = "itm4n/PrintSpoofer" nocase ascii wide
                        $string5 = /PrintSpoofer\sv\%ws\s\(by\s\@itm4n\)/ nocase ascii wide
                        $string6 = /PrintSpoofer\.cpp/ nocase ascii wide
                        $string7 = /PrintSpoofer\.exe/ nocase ascii wide
                        $string8 = /PrintSpoofer\.sln/ nocase ascii wide
                        $string9 = /PrintSpoofer32\.exe/ nocase ascii wide
                        $string10 = /PrintSpoofer64\.exe/ nocase ascii wide

    condition:
        any of them
}