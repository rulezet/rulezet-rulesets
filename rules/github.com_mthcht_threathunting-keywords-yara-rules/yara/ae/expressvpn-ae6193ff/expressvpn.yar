rule ExpressVPN
{
    meta:
        description = "Detection patterns for the tool 'ExpressVPN' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExpressVPN"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "fgddmllnllkalaagkghckoinaemmogpe" nocase ascii wide

    condition:
        any of them
}