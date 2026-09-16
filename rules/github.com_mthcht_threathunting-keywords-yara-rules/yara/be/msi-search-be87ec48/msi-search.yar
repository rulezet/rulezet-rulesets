rule msi_search
{
    meta:
        description = "Detection patterns for the tool 'msi-search' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msi-search"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/msi_search\.ps1/ nocase ascii wide
                        $string2 = /\/msi\-search\.git/ nocase ascii wide
                        $string3 = /\\msi_search\.c/ nocase ascii wide
                        $string4 = /\\msi_search\.exe/ nocase ascii wide
                        $string5 = /\\msi_search\.ps1/ nocase ascii wide
                        $string6 = /\\msi_search\.x64\.o/ nocase ascii wide
                        $string7 = /\\msi_search\.x86\.o/ nocase ascii wide
                        $string8 = "mandiant/msi-search" nocase ascii wide
                        $string9 = /msi\-search\-main\.zip/ nocase ascii wide
                        $string10 = "Search cached MSI files in C:/Windows/Installer/" nocase ascii wide

    condition:
        any of them
}