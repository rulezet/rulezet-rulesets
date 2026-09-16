rule rule_onedrive_user_enum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'onedrive_user_enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onedrive_user_enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_onedrive_user_enum_offensive_tool_keyword = "/onedrive_user_enum" nocase ascii wide
                        $string2_onedrive_user_enum_offensive_tool_keyword = /\-my\.sharepoint\.com\/personal\/Fakeuser/ nocase ascii wide
                        $string3_onedrive_user_enum_offensive_tool_keyword = /\-my\.sharepoint\.com\/personal\/TESTUSER_/ nocase ascii wide
                        $string4_onedrive_user_enum_offensive_tool_keyword = /onedrive_enum\.py/ nocase ascii wide
                        $string5_onedrive_user_enum_offensive_tool_keyword = /onedrive_user_enum\.git/ nocase ascii wide

    condition:
        any of them
}