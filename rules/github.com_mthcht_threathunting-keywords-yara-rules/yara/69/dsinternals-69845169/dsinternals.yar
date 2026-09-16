rule DSInternals
{
    meta:
        description = "Detection patterns for the tool 'DSInternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DSInternals"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sDSInternals\.psd1/ nocase ascii wide
                        $string2 = /\sGet\-ADReplAccount\s\-SamAccountName\s\'AZUREADSSOACC\$\'\s/ nocase ascii wide
                        $string3 = /\/DSInternals\.psd1/ nocase ascii wide
                        $string4 = /\\DSInternals\.psd1/ nocase ascii wide
                        $string5 = /DSInternals_v4\..{0,1000}\.zip/ nocase ascii wide
                        $string6 = /Get\-ADDBAccount\s.{0,1000}\s\-DataBasePath\s.{0,1000}ntds\.dit/ nocase ascii wide
                        $string7 = /Get\-ADDBAccount\s.{0,1000}\s\-DBPath\s.{0,1000}ntds\.dit/ nocase ascii wide
                        $string8 = /Get\-ADDBAccount\s\-All\s\-DBPath\s.{0,1000}\.ntds\.dit.{0,1000}\s\-BootKey/ nocase ascii wide
                        $string9 = /Get\-ADDBAccount.{0,1000}\s\-BootKey.{0,1000}\s\-DataBasePath\s.{0,1000}\.ntds\.dit/ nocase ascii wide
                        $string10 = /Get\-ADDBAccount.{0,1000}\s\-BootKey.{0,1000}\s\-DBPath\s.{0,1000}\.ntds\.dit/ nocase ascii wide
                        $string11 = /Get\-ADDBAccount.{0,1000}\s\-DataBasePath\s.{0,1000}\.ntds\.dit.{0,1000}\s\-BootKey/ nocase ascii wide
                        $string12 = "Get-ADReplAccount -All " nocase ascii wide
                        $string13 = "Import-Module DSInternals" nocase ascii wide
                        $string14 = "Install-Module -Name DSInternals" nocase ascii wide
                        $string15 = /Set\-SamAccountPasswordHash\s.{0,1000}\s\-NTHash\s/ nocase ascii wide
                        $string16 = "Test-PasswordQuality -WeakPasswordHashesSortedFile " nocase ascii wide

    condition:
        any of them
}