rule rule_HoneypotBuster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HoneypotBuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HoneypotBuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HoneypotBuster_offensive_tool_keyword = /\\InactiveDomainAdmins\.csv/ nocase ascii wide
                        $string2_HoneypotBuster_offensive_tool_keyword = "7H0LmBxFtXBPd0/3vHe7Z3dmdrPZmTzp3ZldQrJ5LOGxeZ" nocase ascii wide
                        $string3_HoneypotBuster_offensive_tool_keyword = "7L0LgBxFtTDc093TPe/dntnM7G6Sncm" nocase ascii wide
                        $string4_HoneypotBuster_offensive_tool_keyword = "Fake Computer Objects Honey Pots" nocase ascii wide
                        $string5_HoneypotBuster_offensive_tool_keyword = "Fake Service Accounts Honey Tokens" nocase ascii wide
                        $string6_HoneypotBuster_offensive_tool_keyword = "Get-FakeServiceUsers" nocase ascii wide
                        $string7_HoneypotBuster_offensive_tool_keyword = "Get-InactiveDomainAdmins" nocase ascii wide
                        $string8_HoneypotBuster_offensive_tool_keyword = "Inactive Domain Admins Honey Tokens" nocase ascii wide
                        $string9_HoneypotBuster_offensive_tool_keyword = /InjectedCredentials\.csv/ nocase ascii wide
                        $string10_HoneypotBuster_offensive_tool_keyword = "Invoke-HoneypotBuster" nocase ascii wide

    condition:
        any of them
}