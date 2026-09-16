rule Persistence_Accessibility_Features
{
    meta:
        description = "Detection patterns for the tool 'Persistence-Accessibility-Features' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Persistence-Accessibility-Features"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sstickykey\.ps1/ nocase ascii wide
                        $string2 = "# Sticky Keys backdoor exists" nocase ascii wide
                        $string3 = /\/Persistence\-Accessibility\-Features\.git/ nocase ascii wide
                        $string4 = /\/stickykey\.ps1/ nocase ascii wide
                        $string5 = /\\stickykey\.ps1/ nocase ascii wide
                        $string6 = "3c55b7897d676bc6ec3be27026b32389107e2bba443b52f25674fdc7e4229012" nocase ascii wide
                        $string7 = "Attempting to add Sticky Keys backdoor to registry" nocase ascii wide
                        $string8 = "Attempting to add Sticky Keys backdoor to registry" nocase ascii wide
                        $string9 = "Ignitetechnologies/Persistence-Accessibility-Features" nocase ascii wide
                        $string10 = "Persistence-Accessibility-Features-master" nocase ascii wide
                        $string11 = "Sticky Key backdoor has been removed" nocase ascii wide
                        $string12 = /Sticky\sKeys\sbackdoor\sadded\./ nocase ascii wide
                        $string13 = "Sticky Keys backdoor does not exist, let's add it" nocase ascii wide

    condition:
        any of them
}