rule rule_BOINC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BOINC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOINC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BOINC_offensive_tool_keyword = /discordapp\.com\/attachments\/.{0,1000}\/BOINCPortable_.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}