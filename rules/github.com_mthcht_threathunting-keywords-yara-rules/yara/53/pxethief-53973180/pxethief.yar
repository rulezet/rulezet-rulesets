rule pxethief
{
    meta:
        description = "Detection patterns for the tool 'pxethief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pxethief"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/PXEThief" nocase ascii wide
                        $string2 = "auto_exploit_blank_password" nocase ascii wide
                        $string3 = /media_variable_file_cryptography\.py/ nocase ascii wide
                        $string4 = "pxethief " nocase ascii wide
                        $string5 = /pxethief\.py/ nocase ascii wide

    condition:
        any of them
}