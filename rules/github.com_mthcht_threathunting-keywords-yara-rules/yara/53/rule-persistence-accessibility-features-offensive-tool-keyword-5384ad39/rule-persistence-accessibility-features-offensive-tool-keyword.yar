rule rule_Persistence_Accessibility_Features_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Persistence-Accessibility-Features' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Persistence-Accessibility-Features"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Persistence_Accessibility_Features_offensive_tool_keyword = /\sstickykey\.ps1/ nocase ascii wide
                        $string2_Persistence_Accessibility_Features_offensive_tool_keyword = "# Sticky Keys backdoor exists" nocase ascii wide
                        $string3_Persistence_Accessibility_Features_offensive_tool_keyword = /\/Persistence\-Accessibility\-Features\.git/ nocase ascii wide
                        $string4_Persistence_Accessibility_Features_offensive_tool_keyword = /\/stickykey\.ps1/ nocase ascii wide
                        $string5_Persistence_Accessibility_Features_offensive_tool_keyword = /\\stickykey\.ps1/ nocase ascii wide
                        $string6_Persistence_Accessibility_Features_offensive_tool_keyword = "3c55b7897d676bc6ec3be27026b32389107e2bba443b52f25674fdc7e4229012" nocase ascii wide
                        $string7_Persistence_Accessibility_Features_offensive_tool_keyword = "Attempting to add Sticky Keys backdoor to registry" nocase ascii wide
                        $string8_Persistence_Accessibility_Features_offensive_tool_keyword = "Attempting to add Sticky Keys backdoor to registry" nocase ascii wide
                        $string9_Persistence_Accessibility_Features_offensive_tool_keyword = "Ignitetechnologies/Persistence-Accessibility-Features" nocase ascii wide
                        $string10_Persistence_Accessibility_Features_offensive_tool_keyword = "Persistence-Accessibility-Features-master" nocase ascii wide
                        $string11_Persistence_Accessibility_Features_offensive_tool_keyword = "Sticky Key backdoor has been removed" nocase ascii wide
                        $string12_Persistence_Accessibility_Features_offensive_tool_keyword = /Sticky\sKeys\sbackdoor\sadded\./ nocase ascii wide
                        $string13_Persistence_Accessibility_Features_offensive_tool_keyword = "Sticky Keys backdoor does not exist, let's add it" nocase ascii wide

    condition:
        any of them
}