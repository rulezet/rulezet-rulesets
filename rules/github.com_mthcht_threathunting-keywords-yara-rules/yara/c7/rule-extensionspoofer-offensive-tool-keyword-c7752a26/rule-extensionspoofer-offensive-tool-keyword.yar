rule rule_ExtensionSpoofer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ExtensionSpoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtensionSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ExtensionSpoofer_offensive_tool_keyword = /\sExtensionSpoof\.exe/ nocase ascii wide
                        $string2_ExtensionSpoofer_offensive_tool_keyword = /\/ExtensionSpoof\.exe/ nocase ascii wide
                        $string3_ExtensionSpoofer_offensive_tool_keyword = /\/ExtensionSpoofer\.git/ nocase ascii wide
                        $string4_ExtensionSpoofer_offensive_tool_keyword = /\\ExtensionSpoof\.exe/ nocase ascii wide
                        $string5_ExtensionSpoofer_offensive_tool_keyword = /\\ExtensionSpoof\.sln/ nocase ascii wide
                        $string6_ExtensionSpoofer_offensive_tool_keyword = /\\ExtensionSpoofer\\/ nocase ascii wide
                        $string7_ExtensionSpoofer_offensive_tool_keyword = /ExtensionSpoof\.vbproj/ nocase ascii wide
                        $string8_ExtensionSpoofer_offensive_tool_keyword = /ExtensionSpoof\.xml/ nocase ascii wide
                        $string9_ExtensionSpoofer_offensive_tool_keyword = /ExtensionSpoofer\-1\.zip/ nocase ascii wide
                        $string10_ExtensionSpoofer_offensive_tool_keyword = "FCD5E13D-1663-4226-8280-1C6A97933AB7" nocase ascii wide
                        $string11_ExtensionSpoofer_offensive_tool_keyword = "henriksb/ExtensionSpoofer" nocase ascii wide

    condition:
        any of them
}