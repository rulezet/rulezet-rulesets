rule rule_Spyndicapped_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Spyndicapped' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spyndicapped"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Spyndicapped_offensive_tool_keyword = /\.exe\sspy\s\-\-pid\s/ nocase ascii wide
                        $string2_Spyndicapped_offensive_tool_keyword = /\.exe\sspy\s\-\-window\s/ nocase ascii wide
                        $string3_Spyndicapped_offensive_tool_keyword = /\/Spyndicapped\.exe/ nocase ascii wide
                        $string4_Spyndicapped_offensive_tool_keyword = /\/Spyndicapped\.git/ nocase ascii wide
                        $string5_Spyndicapped_offensive_tool_keyword = /\\Spyndicapped\.exe/ nocase ascii wide
                        $string6_Spyndicapped_offensive_tool_keyword = /\\Spyndicapped_dev\\/ nocase ascii wide
                        $string7_Spyndicapped_offensive_tool_keyword = /\\Spyndicapped\-main/ nocase ascii wide
                        $string8_Spyndicapped_offensive_tool_keyword = "01ae8b32692998eefc9b050e189672ebbc6e356355fc5777957830fd8a067028" nocase ascii wide
                        $string9_Spyndicapped_offensive_tool_keyword = "91ee16300f9af0ed8c9de365bcb3eeb8e1cf0d7b8b75ce8866ccaf8433fef75a" nocase ascii wide
                        $string10_Spyndicapped_offensive_tool_keyword = "cd9c66c8-8fcb-4d43-975b-a9c8d02ad090" nocase ascii wide
                        $string11_Spyndicapped_offensive_tool_keyword = "CICADA8-Research/Spyndicapped" nocase ascii wide
                        $string12_Spyndicapped_offensive_tool_keyword = "Spyndicapped spy " nocase ascii wide
                        $string13_Spyndicapped_offensive_tool_keyword = "Started spying using MyAutomationEventHandler" nocase ascii wide

    condition:
        any of them
}