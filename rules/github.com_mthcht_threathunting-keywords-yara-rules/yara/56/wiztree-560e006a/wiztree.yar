rule wiztree
{
    meta:
        description = "Detection patterns for the tool 'wiztree' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiztree"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\Program\sFiles\\WizTree/ nocase ascii wide
                        $string2 = /\\Temp\\WizTree\.exe/ nocase ascii wide
                        $string3 = /\\WizTree\.exe/ nocase ascii wide
                        $string4 = /\\wiztree_.{0,1000}_portable\.zip.{0,1000}	/ nocase ascii wide
                        $string5 = /http\:\/\/antibody\-software\.com\/files\/wiztreeversion\.php/ nocase ascii wide
                        $string6 = "WizTreeMutex" nocase ascii wide

    condition:
        any of them
}