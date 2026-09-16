rule rule_LAPSDecrypt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LAPSDecrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LAPSDecrypt_offensive_tool_keyword = /LAPSDecrypt\./ nocase ascii wide

    condition:
        any of them
}