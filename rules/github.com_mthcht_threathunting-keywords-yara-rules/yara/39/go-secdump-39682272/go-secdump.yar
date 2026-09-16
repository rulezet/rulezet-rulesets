rule go_secdump
{
    meta:
        description = "Detection patterns for the tool 'go-secdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-secdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/go\-secdump/
                        $string2 = /\/go\-secdump\.git/ nocase ascii wide
                        $string3 = /\\go\-secdump/ nocase ascii wide
                        $string4 = "go-secdump -" nocase ascii wide
                        $string5 = /go\-secdump\.exe/ nocase ascii wide
                        $string6 = "go-secdump-main" nocase ascii wide
                        $string7 = "jfjallid/go-secdump" nocase ascii wide

    condition:
        any of them
}