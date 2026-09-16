rule rule_dropbox_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dropbox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropbox"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dropbox_greyware_tool_keyword = /https\:\/\/content\.dropboxapi\.com\/2\/files\/upload/ nocase ascii wide

    condition:
        any of them
}