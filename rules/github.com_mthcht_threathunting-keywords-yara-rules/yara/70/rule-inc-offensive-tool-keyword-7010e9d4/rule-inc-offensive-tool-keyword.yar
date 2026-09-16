rule rule_Inc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Inc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Inc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Inc_offensive_tool_keyword = /\sdelete\sshadow\scopies\sfrom\s.{0,1000}c\:\/\s/ nocase ascii wide
                        $string2_Inc_offensive_tool_keyword = /\[.{0,1000}\]\sStarting\sfull\sencryption\sin\s5s/ nocase ascii wide
                        $string3_Inc_offensive_tool_keyword = /PGh0bWw\+DQoJPGhlYWQ\+DQoJCTx0aXRsZT5JbmMuIFJhbnNvbXdhcmU8/ nocase ascii wide

    condition:
        any of them
}