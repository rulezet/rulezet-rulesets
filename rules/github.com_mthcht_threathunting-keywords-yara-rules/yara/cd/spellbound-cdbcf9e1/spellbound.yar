rule spellbound
{
    meta:
        description = "Detection patterns for the tool 'spellbound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spellbound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sspellgen\.py\s/ nocase ascii wide
                        $string2 = /\sspellstager\.py\s/ nocase ascii wide
                        $string3 = /\/spellbound\.git/ nocase ascii wide
                        $string4 = /\/spellgen\.py\s/ nocase ascii wide
                        $string5 = /\/spellstager\.py\s/ nocase ascii wide
                        $string6 = /\\spellbound\-main/ nocase ascii wide
                        $string7 = /\\spellgen\.py\s/ nocase ascii wide
                        $string8 = /\\spellstager\.py\s/ nocase ascii wide
                        $string9 = "5dec1cfe7c0c2ec55c17fb44b43f7d14" nocase ascii wide
                        $string10 = "mhuzaifi0604/spellbound" nocase ascii wide
                        $string11 = /payload_msf\.c/ nocase ascii wide
                        $string12 = /payload_msf\.exe/ nocase ascii wide
                        $string13 = /payload_spellshell\.c/ nocase ascii wide
                        $string14 = /payload_spellshell\.exe/ nocase ascii wide

    condition:
        any of them
}