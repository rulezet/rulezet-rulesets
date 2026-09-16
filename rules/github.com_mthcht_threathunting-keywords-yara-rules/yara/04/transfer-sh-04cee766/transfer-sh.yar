rule transfer_sh
{
    meta:
        description = "Detection patterns for the tool 'transfer.sh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfer.sh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /https\:\/\/transfer\.sh\/get\/.{0,1000}\/.{0,1000}\.pdf/ nocase ascii wide
                        $string2 = /https\:\/\/transfer\.sh\/get\/.{0,1000}\/.{0,1000}\.py/ nocase ascii wide

    condition:
        any of them
}