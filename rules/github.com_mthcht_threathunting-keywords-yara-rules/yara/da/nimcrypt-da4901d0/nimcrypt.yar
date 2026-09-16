rule nimcrypt
{
    meta:
        description = "Detection patterns for the tool 'nimcrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimcrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " nimcrypt" nocase ascii wide
                        $string2 = /\/nimcrypt\.nim/ nocase ascii wide
                        $string3 = "/nimcrypt/" nocase ascii wide
                        $string4 = "nimcrypt --file " nocase ascii wide
                        $string5 = "--out=nimcrypt" nocase ascii wide

    condition:
        any of them
}