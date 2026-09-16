rule rule_keylogger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'keylogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_keylogger_offensive_tool_keyword = /\/keylogger\.exe/ nocase ascii wide
                        $string2_keylogger_offensive_tool_keyword = /\/keylogger\.git/ nocase ascii wide
                        $string3_keylogger_offensive_tool_keyword = /\\keylogger\.exe/ nocase ascii wide
                        $string4_keylogger_offensive_tool_keyword = "8340cdf3b69ba92b47803f75eabb102d35454ef9676702ff1742c7136d9608de" nocase ascii wide
                        $string5_keylogger_offensive_tool_keyword = "Keylogger" nocase ascii wide
                        $string6_keylogger_offensive_tool_keyword = "uknowsec/keylogger" nocase ascii wide

    condition:
        any of them
}