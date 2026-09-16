rule TheFatRat
{
    meta:
        description = "Detection patterns for the tool 'TheFatRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TheFatRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/backdoor_apk"
                        $string2 = /\/cred_dump\.rc/
                        $string3 = "/TheFatRat"

    condition:
        any of them
}