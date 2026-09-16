rule transfer_sh
{
    meta:
        description = "Detection patterns for the tool 'transfer.sh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfer.sh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/transfer\.sh/ nocase ascii wide

    condition:
        any of them
}