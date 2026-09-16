rule rule_RevoUninstaller_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RevoUninstaller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RevoUninstaller"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_RevoUninstaller_greyware_tool_keyword = /\/RevoUninProSetup\.exe/ nocase ascii wide
                        $string2_RevoUninstaller_greyware_tool_keyword = /\\RevoUninProSetup\.exe/ nocase ascii wide

    condition:
        any of them
}