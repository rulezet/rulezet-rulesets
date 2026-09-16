rule HoneypotBuster
{
    meta:
        description = "Detection patterns for the tool 'HoneypotBuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HoneypotBuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\InactiveDomainAdmins\.csv/ nocase ascii wide
                        $string2 = "7H0LmBxFtXBPd0/3vHe7Z3dmdrPZmTzp3ZldQrJ5LOGxeZ" nocase ascii wide
                        $string3 = "7L0LgBxFtTDc093TPe/dntnM7G6Sncm" nocase ascii wide
                        $string4 = "Fake Computer Objects Honey Pots" nocase ascii wide
                        $string5 = "Fake Service Accounts Honey Tokens" nocase ascii wide
                        $string6 = "Get-FakeServiceUsers" nocase ascii wide
                        $string7 = "Get-InactiveDomainAdmins" nocase ascii wide
                        $string8 = "Inactive Domain Admins Honey Tokens" nocase ascii wide
                        $string9 = /InjectedCredentials\.csv/ nocase ascii wide
                        $string10 = "Invoke-HoneypotBuster" nocase ascii wide

    condition:
        any of them
}