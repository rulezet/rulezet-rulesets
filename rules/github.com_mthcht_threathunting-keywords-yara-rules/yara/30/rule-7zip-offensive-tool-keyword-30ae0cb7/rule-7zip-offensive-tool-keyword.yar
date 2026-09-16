rule rule__7zip_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '7zip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "7zip"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__7zip_offensive_tool_keyword = /7\.exe\sa\s\-mx3\sad\.7z\sad_.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}