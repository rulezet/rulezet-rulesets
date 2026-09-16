rule TokenTactics
{
    meta:
        description = "Detection patterns for the tool 'TokenTactics' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenTactics"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/CapBypass\.ps1/ nocase ascii wide
                        $string2 = "/rvrsh3ll/" nocase ascii wide
                        $string3 = /\/TokenTactics\.git/ nocase ascii wide
                        $string4 = /capturetokenphish\.ps1/ nocase ascii wide
                        $string5 = /capturetokenphish\.py/ nocase ascii wide
                        $string6 = "Connect-AzureAD -AadAccessToken -AccountId " nocase ascii wide
                        $string7 = /deploycaptureserver\.ps1/ nocase ascii wide
                        $string8 = "Invoke-DumpOWAMailboxViaMSGraphApi" nocase ascii wide
                        $string9 = "Invoke-ForgeUserAgent" nocase ascii wide
                        $string10 = "Invoke-OpenOWAMailboxInBrowser" nocase ascii wide
                        $string11 = "Invoke-RefreshToMSGraphToken -domain -ClientId " nocase ascii wide
                        $string12 = /OutlookEmailAbuse\.ps1/ nocase ascii wide
                        $string13 = "rvrsh3ll/TokenTactics" nocase ascii wide
                        $string14 = /TokenTactics\.psd1/ nocase ascii wide
                        $string15 = /TokenTactics\.psm1/ nocase ascii wide
                        $string16 = /TokenTactics\-main\.zip/ nocase ascii wide

    condition:
        any of them
}