rule GhostMapper
{
    meta:
        description = "Detection patterns for the tool 'GhostMapper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostMapper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/GhostMapper\.git/ nocase ascii wide
                        $string2 = /\/GhostMapper\.sln/ nocase ascii wide
                        $string3 = /\\GhostMapper\.sln/ nocase ascii wide
                        $string4 = "4D7BA537-54EC-4005-9CC2-AE134B4526F9" nocase ascii wide
                        $string5 = /GhostMapper\-main\./ nocase ascii wide
                        $string6 = "Oliver-1-1/GhostMapper" nocase ascii wide

    condition:
        any of them
}