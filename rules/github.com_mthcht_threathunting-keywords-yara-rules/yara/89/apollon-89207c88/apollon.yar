rule apollon
{
    meta:
        description = "Detection patterns for the tool 'apollon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apollon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/apollon-all-x64" nocase ascii wide
                        $string2 = /\/apollon\-main\.zip/ nocase ascii wide
                        $string3 = "/apollon-selective-x64" nocase ascii wide
                        $string4 = /\[\-\]\sSeems\slike\swe\skilled\sauditd\.\sOoopsie\s\:D/ nocase ascii wide
                        $string5 = /\[\+\]\sauditd\spatched\ssuccessfully/ nocase ascii wide
                        $string6 = "codewhitesec/apollon" nocase ascii wide

    condition:
        any of them
}