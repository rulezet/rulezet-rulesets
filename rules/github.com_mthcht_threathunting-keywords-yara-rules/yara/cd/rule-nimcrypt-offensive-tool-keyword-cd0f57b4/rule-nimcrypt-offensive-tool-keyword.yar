rule rule_nimcrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nimcrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimcrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nimcrypt_offensive_tool_keyword = " nimcrypt" nocase ascii wide
                        $string2_nimcrypt_offensive_tool_keyword = /\/nimcrypt\.nim/ nocase ascii wide
                        $string3_nimcrypt_offensive_tool_keyword = "/nimcrypt/" nocase ascii wide
                        $string4_nimcrypt_offensive_tool_keyword = "nimcrypt --file " nocase ascii wide
                        $string5_nimcrypt_offensive_tool_keyword = "--out=nimcrypt" nocase ascii wide

    condition:
        any of them
}