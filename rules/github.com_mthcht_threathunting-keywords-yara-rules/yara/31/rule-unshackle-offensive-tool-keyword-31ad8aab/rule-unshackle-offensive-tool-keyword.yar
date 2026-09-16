rule rule_unshackle_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unshackle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshackle"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_unshackle_offensive_tool_keyword = "/bin/unshackle"
                        $string2_unshackle_offensive_tool_keyword = /\/unshackle\.git/
                        $string3_unshackle_offensive_tool_keyword = /\/unshackle\.modules/
                        $string4_unshackle_offensive_tool_keyword = "Fadi002/unshackle"
                        $string5_unshackle_offensive_tool_keyword = "unshackle --"
                        $string6_unshackle_offensive_tool_keyword = "unshackle-main"
                        $string7_unshackle_offensive_tool_keyword = /unshackle\-v1\.0\.iso/

    condition:
        any of them
}