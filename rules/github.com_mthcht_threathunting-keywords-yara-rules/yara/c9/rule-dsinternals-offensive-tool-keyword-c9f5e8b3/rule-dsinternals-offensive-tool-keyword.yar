rule rule_DSInternals_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DSInternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DSInternals"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DSInternals_offensive_tool_keyword = /\sDSInternals\.psd1/ nocase ascii wide
                        $string2_DSInternals_offensive_tool_keyword = /\sGet\-ADReplAccount\s\-SamAccountName\s\'AZUREADSSOACC\$\'\s/ nocase ascii wide
                        $string3_DSInternals_offensive_tool_keyword = /\/DSInternals\.psd1/ nocase ascii wide
                        $string4_DSInternals_offensive_tool_keyword = /\\DSInternals\.psd1/ nocase ascii wide
                        $string5_DSInternals_offensive_tool_keyword = /DSInternals_v4\..{0,1000}\.zip/ nocase ascii wide
                        $string6_DSInternals_offensive_tool_keyword = /Get\-ADDBAccount\s.{0,1000}\s\-DataBasePath\s.{0,1000}ntds\.dit/ nocase ascii wide
                        $string7_DSInternals_offensive_tool_keyword = /Get\-ADDBAccount\s.{0,1000}\s\-DBPath\s.{0,1000}ntds\.dit/ nocase ascii wide
                        $string8_DSInternals_offensive_tool_keyword = /Get\-ADDBAccount\s\-All\s\-DBPath\s.{0,1000}\.ntds\.dit.{0,1000}\s\-BootKey/ nocase ascii wide
                        $string9_DSInternals_offensive_tool_keyword = /Get\-ADDBAccount.{0,1000}\s\-BootKey.{0,1000}\s\-DataBasePath\s.{0,1000}\.ntds\.dit/ nocase ascii wide
                        $string10_DSInternals_offensive_tool_keyword = /Get\-ADDBAccount.{0,1000}\s\-BootKey.{0,1000}\s\-DBPath\s.{0,1000}\.ntds\.dit/ nocase ascii wide
                        $string11_DSInternals_offensive_tool_keyword = /Get\-ADDBAccount.{0,1000}\s\-DataBasePath\s.{0,1000}\.ntds\.dit.{0,1000}\s\-BootKey/ nocase ascii wide
                        $string12_DSInternals_offensive_tool_keyword = "Get-ADReplAccount -All " nocase ascii wide
                        $string13_DSInternals_offensive_tool_keyword = "Import-Module DSInternals" nocase ascii wide
                        $string14_DSInternals_offensive_tool_keyword = "Install-Module -Name DSInternals" nocase ascii wide
                        $string15_DSInternals_offensive_tool_keyword = /Set\-SamAccountPasswordHash\s.{0,1000}\s\-NTHash\s/ nocase ascii wide
                        $string16_DSInternals_offensive_tool_keyword = "Test-PasswordQuality -WeakPasswordHashesSortedFile " nocase ascii wide

    condition:
        any of them
}