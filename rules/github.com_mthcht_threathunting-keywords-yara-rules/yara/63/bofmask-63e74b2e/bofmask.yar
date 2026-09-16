rule BOFMask
{
    meta:
        description = "Detection patterns for the tool 'BOFMask' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOFMask"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BOFMask\.git/ nocase ascii wide
                        $string2 = /\/bofmask\.h/ nocase ascii wide
                        $string3 = "BOFMask-main" nocase ascii wide
                        $string4 = /include.{0,1000}bofmask\.h/ nocase ascii wide
                        $string5 = "passthehashbrowns/BOFMask" nocase ascii wide

    condition:
        any of them
}