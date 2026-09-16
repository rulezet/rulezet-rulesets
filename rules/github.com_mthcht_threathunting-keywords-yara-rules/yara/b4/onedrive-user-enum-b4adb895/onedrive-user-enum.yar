rule onedrive_user_enum
{
    meta:
        description = "Detection patterns for the tool 'onedrive_user_enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onedrive_user_enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/onedrive_user_enum" nocase ascii wide
                        $string2 = /\-my\.sharepoint\.com\/personal\/Fakeuser/ nocase ascii wide
                        $string3 = /\-my\.sharepoint\.com\/personal\/TESTUSER_/ nocase ascii wide
                        $string4 = /onedrive_enum\.py/ nocase ascii wide
                        $string5 = /onedrive_user_enum\.git/ nocase ascii wide

    condition:
        any of them
}