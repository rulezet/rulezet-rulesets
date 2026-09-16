rule rule_Cable_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cable' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cable"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Cable_offensive_tool_keyword = /\.NET\spost\-exploitation\stoolkit\sfor\sActive\sDirectory\sreconnaissance\sand\sexploitation\s/ nocase ascii wide
                        $string2_Cable_offensive_tool_keyword = /\[\-\]\sNo\sKerberoastable\saccounts\sfound/ nocase ascii wide
                        $string3_Cable_offensive_tool_keyword = /\[\+\]\sFinding\sKerberoastable\saccounts/ nocase ascii wide
                        $string4_Cable_offensive_tool_keyword = /\[\+\]\sSID\sadded\sto\smsDS\-AllowedToActOnBehalfOfOtherIdentity/ nocase ascii wide
                        $string5_Cable_offensive_tool_keyword = "06B2AE2B-7FD3-4C36-B825-1594752B1D7B" nocase ascii wide
                        $string6_Cable_offensive_tool_keyword = "16717cf09d49d252b21c5768092a557ea5a7899d781656da909a7766b6c55074" nocase ascii wide
                        $string7_Cable_offensive_tool_keyword = "fff1c91cf41743e46dc2b43b256680ce9015d0a705b31cf19c2cfb48f48c616f" nocase ascii wide
                        $string8_Cable_offensive_tool_keyword = "logangoins/Cable" nocase ascii wide

    condition:
        any of them
}