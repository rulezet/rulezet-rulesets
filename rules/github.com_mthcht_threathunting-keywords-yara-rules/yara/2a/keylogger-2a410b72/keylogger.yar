rule keylogger
{
    meta:
        description = "Detection patterns for the tool 'keylogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/keylogger\.exe/ nocase ascii wide
                        $string2 = /\/keylogger\.git/ nocase ascii wide
                        $string3 = /\\keylogger\.exe/ nocase ascii wide
                        $string4 = "8340cdf3b69ba92b47803f75eabb102d35454ef9676702ff1742c7136d9608de" nocase ascii wide
                        $string5 = "Keylogger" nocase ascii wide
                        $string6 = "uknowsec/keylogger" nocase ascii wide

    condition:
        any of them
}