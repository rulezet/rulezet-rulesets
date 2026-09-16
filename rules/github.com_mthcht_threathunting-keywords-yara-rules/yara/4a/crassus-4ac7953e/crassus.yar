rule Crassus
{
    meta:
        description = "Detection patterns for the tool 'Crassus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crassus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Crassus\.git/ nocase ascii wide
                        $string2 = "/Crassus-main" nocase ascii wide
                        $string3 = /\\Crassus\-main/ nocase ascii wide
                        $string4 = "7E9729AA-4CF2-4D0A-8183-7FB7CE7A5B1A" nocase ascii wide
                        $string5 = /Crassus\.csproj/ nocase ascii wide
                        $string6 = /Crassus\.exe/ nocase ascii wide
                        $string7 = /Crassus\.sln/ nocase ascii wide
                        $string8 = "vu-ls/Crassus" nocase ascii wide

    condition:
        any of them
}