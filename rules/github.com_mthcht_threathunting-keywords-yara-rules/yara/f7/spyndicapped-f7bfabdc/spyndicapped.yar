rule Spyndicapped
{
    meta:
        description = "Detection patterns for the tool 'Spyndicapped' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spyndicapped"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sspy\s\-\-pid\s/ nocase ascii wide
                        $string2 = /\.exe\sspy\s\-\-window\s/ nocase ascii wide
                        $string3 = /\/Spyndicapped\.exe/ nocase ascii wide
                        $string4 = /\/Spyndicapped\.git/ nocase ascii wide
                        $string5 = /\\Spyndicapped\.exe/ nocase ascii wide
                        $string6 = /\\Spyndicapped_dev\\/ nocase ascii wide
                        $string7 = /\\Spyndicapped\-main/ nocase ascii wide
                        $string8 = "01ae8b32692998eefc9b050e189672ebbc6e356355fc5777957830fd8a067028" nocase ascii wide
                        $string9 = "91ee16300f9af0ed8c9de365bcb3eeb8e1cf0d7b8b75ce8866ccaf8433fef75a" nocase ascii wide
                        $string10 = "cd9c66c8-8fcb-4d43-975b-a9c8d02ad090" nocase ascii wide
                        $string11 = "CICADA8-Research/Spyndicapped" nocase ascii wide
                        $string12 = "Spyndicapped spy " nocase ascii wide
                        $string13 = "Started spying using MyAutomationEventHandler" nocase ascii wide

    condition:
        any of them
}