rule rule_AzureAD_Autologon_Brute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AzureAD_Autologon_Brute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AzureAD_Autologon_Brute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AzureAD_Autologon_Brute_offensive_tool_keyword = "AzureAD AutoLogon Brute" nocase ascii wide
                        $string2_AzureAD_Autologon_Brute_offensive_tool_keyword = "AzureAD_Autologon_Brute" nocase ascii wide

    condition:
        any of them
}