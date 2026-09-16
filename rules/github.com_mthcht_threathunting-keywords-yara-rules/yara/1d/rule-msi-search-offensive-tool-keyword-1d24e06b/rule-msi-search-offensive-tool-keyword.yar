rule rule_msi_search_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'msi-search' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msi-search"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_msi_search_offensive_tool_keyword = /\/msi_search\.ps1/ nocase ascii wide
                        $string2_msi_search_offensive_tool_keyword = /\/msi\-search\.git/ nocase ascii wide
                        $string3_msi_search_offensive_tool_keyword = /\\msi_search\.c/ nocase ascii wide
                        $string4_msi_search_offensive_tool_keyword = /\\msi_search\.exe/ nocase ascii wide
                        $string5_msi_search_offensive_tool_keyword = /\\msi_search\.ps1/ nocase ascii wide
                        $string6_msi_search_offensive_tool_keyword = /\\msi_search\.x64\.o/ nocase ascii wide
                        $string7_msi_search_offensive_tool_keyword = /\\msi_search\.x86\.o/ nocase ascii wide
                        $string8_msi_search_offensive_tool_keyword = "mandiant/msi-search" nocase ascii wide
                        $string9_msi_search_offensive_tool_keyword = /msi\-search\-main\.zip/ nocase ascii wide
                        $string10_msi_search_offensive_tool_keyword = "Search cached MSI files in C:/Windows/Installer/" nocase ascii wide

    condition:
        any of them
}