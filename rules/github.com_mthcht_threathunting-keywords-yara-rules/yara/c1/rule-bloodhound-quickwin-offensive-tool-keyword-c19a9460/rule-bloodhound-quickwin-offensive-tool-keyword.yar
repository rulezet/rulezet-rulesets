rule rule_bloodhound_quickwin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bloodhound-quickwin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodhound-quickwin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bloodhound_quickwin_offensive_tool_keyword = /\sbhqc\.py\s\-/ nocase ascii wide
                        $string2_bloodhound_quickwin_offensive_tool_keyword = /\/bhqc\.py\s\-/ nocase ascii wide
                        $string3_bloodhound_quickwin_offensive_tool_keyword = /\/bloodhound\-quickwin\.git/ nocase ascii wide
                        $string4_bloodhound_quickwin_offensive_tool_keyword = "bloodhound-quickwin-main" nocase ascii wide
                        $string5_bloodhound_quickwin_offensive_tool_keyword = "kaluche/bloodhound-quickwin" nocase ascii wide

    condition:
        any of them
}