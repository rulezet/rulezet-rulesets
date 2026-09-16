rule ExtensionSpoofer
{
    meta:
        description = "Detection patterns for the tool 'ExtensionSpoofer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtensionSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sExtensionSpoof\.exe/ nocase ascii wide
                        $string2 = /\/ExtensionSpoof\.exe/ nocase ascii wide
                        $string3 = /\/ExtensionSpoofer\.git/ nocase ascii wide
                        $string4 = /\\ExtensionSpoof\.exe/ nocase ascii wide
                        $string5 = /\\ExtensionSpoof\.sln/ nocase ascii wide
                        $string6 = /\\ExtensionSpoofer\\/ nocase ascii wide
                        $string7 = /ExtensionSpoof\.vbproj/ nocase ascii wide
                        $string8 = /ExtensionSpoof\.xml/ nocase ascii wide
                        $string9 = /ExtensionSpoofer\-1\.zip/ nocase ascii wide
                        $string10 = "FCD5E13D-1663-4226-8280-1C6A97933AB7" nocase ascii wide
                        $string11 = "henriksb/ExtensionSpoofer" nocase ascii wide

    condition:
        any of them
}