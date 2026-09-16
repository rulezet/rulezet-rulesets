rule rule_TokenTacticsV2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TokenTacticsV2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenTacticsV2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TokenTacticsV2_offensive_tool_keyword = "\"MSGraph token is CAE capable\"" nocase ascii wide
                        $string2_TokenTacticsV2_offensive_tool_keyword = /\/TokenTacticsV2\.git/ nocase ascii wide
                        $string3_TokenTacticsV2_offensive_tool_keyword = /\\ConvertFrom\-JWTtoken\.ps1/ nocase ascii wide
                        $string4_TokenTacticsV2_offensive_tool_keyword = "4aede7350521d2a3d0975833db870f94c50c8d46c28d8b14f930619e35b4b07e" nocase ascii wide
                        $string5_TokenTacticsV2_offensive_tool_keyword = "8648dfc2aff4508e8469d1ed4a7a775b558527bfb0050ba4ed75db259b07943d" nocase ascii wide
                        $string6_TokenTacticsV2_offensive_tool_keyword = "da9735d88a845e465aa4fe4968df15b97ba4b6565f150a48ead7a3ca7298df93" nocase ascii wide
                        $string7_TokenTacticsV2_offensive_tool_keyword = "dd86be9a1fb1198264e1a01247473be5e1498ef549a91b7c7143e5cfc25784e1" nocase ascii wide
                        $string8_TokenTacticsV2_offensive_tool_keyword = "f-bader/TokenTacticsV2" nocase ascii wide
                        $string9_TokenTacticsV2_offensive_tool_keyword = "Get-AzureTokenFromESTSCookie " nocase ascii wide
                        $string10_TokenTacticsV2_offensive_tool_keyword = "Get-AzureTokenFromESTSCookie -ESTSAuthCookie " nocase ascii wide
                        $string11_TokenTacticsV2_offensive_tool_keyword = "Get-ForgedUserAgent " nocase ascii wide
                        $string12_TokenTacticsV2_offensive_tool_keyword = /Get\-ForgedUserAgent\.ps1/ nocase ascii wide
                        $string13_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToAzureCoreManagementToken " nocase ascii wide
                        $string14_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToAzureManagementToken " nocase ascii wide
                        $string15_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToDODMSGraphToken " nocase ascii wide
                        $string16_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToGraphToken " nocase ascii wide
                        $string17_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToMAMToken " nocase ascii wide
                        $string18_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToMSGraphToken " nocase ascii wide
                        $string19_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToMSManageToken " nocase ascii wide
                        $string20_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToMSTeamsToken " nocase ascii wide
                        $string21_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToOfficeAppsToken " nocase ascii wide
                        $string22_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToOfficeManagementToken " nocase ascii wide
                        $string23_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToOneDriveToken " nocase ascii wide
                        $string24_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToOutlookToken " nocase ascii wide
                        $string25_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToSharePointToken " nocase ascii wide
                        $string26_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToSubstrateToken " nocase ascii wide
                        $string27_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToToken " nocase ascii wide
                        $string28_TokenTacticsV2_offensive_tool_keyword = "Invoke-RefreshToYammerToken " nocase ascii wide
                        $string29_TokenTacticsV2_offensive_tool_keyword = /TokenTactics\.psd1/ nocase ascii wide
                        $string30_TokenTacticsV2_offensive_tool_keyword = /TokenTactics\.psm1/ nocase ascii wide

    condition:
        any of them
}