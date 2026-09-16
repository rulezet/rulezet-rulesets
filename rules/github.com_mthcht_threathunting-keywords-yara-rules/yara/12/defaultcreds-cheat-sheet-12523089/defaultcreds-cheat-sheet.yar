rule DefaultCreds_cheat_sheet
{
    meta:
        description = "Detection patterns for the tool 'DefaultCreds-cheat-sheet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DefaultCreds-cheat-sheet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/creds\-.{0,1000}\/creds\.zip/ nocase ascii wide
                        $string2 = /\/DefaultCreds_db\.json/ nocase ascii wide
                        $string3 = /\/tmp\/.{0,1000}\-passwords\.txt/
                        $string4 = /\/tmp\/.{0,1000}\-usernames\.txt/
                        $string5 = "DefaultCreds-cheat-sheet" nocase ascii wide

    condition:
        any of them
}