rule rule_TokenTactics_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TokenTactics' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenTactics"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TokenTactics_offensive_tool_keyword = /\/CapBypass\.ps1/ nocase ascii wide
                        $string2_TokenTactics_offensive_tool_keyword = "/rvrsh3ll/" nocase ascii wide
                        $string3_TokenTactics_offensive_tool_keyword = /\/TokenTactics\.git/ nocase ascii wide
                        $string4_TokenTactics_offensive_tool_keyword = /capturetokenphish\.ps1/ nocase ascii wide
                        $string5_TokenTactics_offensive_tool_keyword = /capturetokenphish\.py/ nocase ascii wide
                        $string6_TokenTactics_offensive_tool_keyword = "Connect-AzureAD -AadAccessToken -AccountId " nocase ascii wide
                        $string7_TokenTactics_offensive_tool_keyword = /deploycaptureserver\.ps1/ nocase ascii wide
                        $string8_TokenTactics_offensive_tool_keyword = "Invoke-DumpOWAMailboxViaMSGraphApi" nocase ascii wide
                        $string9_TokenTactics_offensive_tool_keyword = "Invoke-ForgeUserAgent" nocase ascii wide
                        $string10_TokenTactics_offensive_tool_keyword = "Invoke-OpenOWAMailboxInBrowser" nocase ascii wide
                        $string11_TokenTactics_offensive_tool_keyword = "Invoke-RefreshToMSGraphToken -domain -ClientId " nocase ascii wide
                        $string12_TokenTactics_offensive_tool_keyword = /OutlookEmailAbuse\.ps1/ nocase ascii wide
                        $string13_TokenTactics_offensive_tool_keyword = "rvrsh3ll/TokenTactics" nocase ascii wide
                        $string14_TokenTactics_offensive_tool_keyword = /TokenTactics\.psd1/ nocase ascii wide
                        $string15_TokenTactics_offensive_tool_keyword = /TokenTactics\.psm1/ nocase ascii wide
                        $string16_TokenTactics_offensive_tool_keyword = /TokenTactics\-main\.zip/ nocase ascii wide

    condition:
        any of them
}