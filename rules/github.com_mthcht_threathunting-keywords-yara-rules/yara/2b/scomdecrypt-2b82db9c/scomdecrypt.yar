rule SCOMDecrypt
{
    meta:
        description = "Detection patterns for the tool 'SCOMDecrypt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCOMDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SCOMDecrypt\.git/ nocase ascii wide
                        $string2 = "1637c5d66df6ce383aee2ab51e305ae9b654cfb4ceb21cf09d5123a54d7d7b7d" nocase ascii wide
                        $string3 = "1b578e26adc91f95143cb5c8dcfa9c0baf76923ea2295cc45e2e7a99bd4a763c" nocase ascii wide
                        $string4 = "5cdec4449506fe06e507619c8f1a66d890d96bb2ea30f6ea37f997853a52b243" nocase ascii wide
                        $string5 = "C13C80ED-ED7A-4F27-93B1-DE6FD30A7B43" nocase ascii wide
                        $string6 = "Invoke-SCOMDecrypt" nocase ascii wide
                        $string7 = "nccgroup/SCOMDecrypt" nocase ascii wide
                        $string8 = /SCOMDecrypt\.csproj/ nocase ascii wide
                        $string9 = /SCOMDecrypt\.exe/ nocase ascii wide
                        $string10 = /SCOMDecrypt\.ps1/ nocase ascii wide

    condition:
        any of them
}