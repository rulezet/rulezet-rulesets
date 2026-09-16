rule rule_spellbound_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spellbound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spellbound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spellbound_offensive_tool_keyword = /\sspellgen\.py\s/ nocase ascii wide
                        $string2_spellbound_offensive_tool_keyword = /\sspellstager\.py\s/ nocase ascii wide
                        $string3_spellbound_offensive_tool_keyword = /\/spellbound\.git/ nocase ascii wide
                        $string4_spellbound_offensive_tool_keyword = /\/spellgen\.py\s/ nocase ascii wide
                        $string5_spellbound_offensive_tool_keyword = /\/spellstager\.py\s/ nocase ascii wide
                        $string6_spellbound_offensive_tool_keyword = /\\spellbound\-main/ nocase ascii wide
                        $string7_spellbound_offensive_tool_keyword = /\\spellgen\.py\s/ nocase ascii wide
                        $string8_spellbound_offensive_tool_keyword = /\\spellstager\.py\s/ nocase ascii wide
                        $string9_spellbound_offensive_tool_keyword = "5dec1cfe7c0c2ec55c17fb44b43f7d14" nocase ascii wide
                        $string10_spellbound_offensive_tool_keyword = "mhuzaifi0604/spellbound" nocase ascii wide
                        $string11_spellbound_offensive_tool_keyword = /payload_msf\.c/ nocase ascii wide
                        $string12_spellbound_offensive_tool_keyword = /payload_msf\.exe/ nocase ascii wide
                        $string13_spellbound_offensive_tool_keyword = /payload_spellshell\.c/ nocase ascii wide
                        $string14_spellbound_offensive_tool_keyword = /payload_spellshell\.exe/ nocase ascii wide

    condition:
        any of them
}