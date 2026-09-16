rule NetSess
{
    meta:
        description = "Detection patterns for the tool 'NetSess' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetSess"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/NetSess\.exe/ nocase ascii wide
                        $string2 = /\/NetSess\.zip/ nocase ascii wide
                        $string3 = /\\NetSess\.exe/ nocase ascii wide
                        $string4 = /\\NetSess\.zip/ nocase ascii wide
                        $string5 = "ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d" nocase ascii wide
                        $string6 = "ddeeedc8ab9ab3b90c2e36340d4674fda3b458c0afd7514735b2857f26b14c6d" nocase ascii wide
                        $string7 = /Get\-NetSessionEnum\.ps1/ nocase ascii wide
                        $string8 = /https\:\/\/www\.joeware\.net\/downloads\/dl2\.php/ nocase ascii wide
                        $string9 = /TEMP\\ns\.exe\s/ nocase ascii wide

    condition:
        any of them
}