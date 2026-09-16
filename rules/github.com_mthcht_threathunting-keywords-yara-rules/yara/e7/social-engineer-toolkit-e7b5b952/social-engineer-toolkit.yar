rule social_engineer_toolkit
{
    meta:
        description = "Detection patterns for the tool 'social-engineer-toolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "social-engineer-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " setoolkit" nocase ascii wide
                        $string2 = "apt install set -y" nocase ascii wide
                        $string3 = "bin/setoolkit" nocase ascii wide
                        $string4 = "setoolkit " nocase ascii wide
                        $string5 = "Social Engineer Toolkit" nocase ascii wide
                        $string6 = "trustedsec/social-engineer-toolkit" nocase ascii wide

    condition:
        any of them
}