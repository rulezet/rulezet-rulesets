rule rule_DefaultCreds_cheat_sheet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DefaultCreds-cheat-sheet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DefaultCreds-cheat-sheet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DefaultCreds_cheat_sheet_offensive_tool_keyword = /\/creds\-.{0,1000}\/creds\.zip/ nocase ascii wide
                        $string2_DefaultCreds_cheat_sheet_offensive_tool_keyword = /\/DefaultCreds_db\.json/ nocase ascii wide
                        $string3_DefaultCreds_cheat_sheet_offensive_tool_keyword = /\/tmp\/.{0,1000}\-passwords\.txt/
                        $string4_DefaultCreds_cheat_sheet_offensive_tool_keyword = /\/tmp\/.{0,1000}\-usernames\.txt/
                        $string5_DefaultCreds_cheat_sheet_offensive_tool_keyword = "DefaultCreds-cheat-sheet" nocase ascii wide

    condition:
        any of them
}