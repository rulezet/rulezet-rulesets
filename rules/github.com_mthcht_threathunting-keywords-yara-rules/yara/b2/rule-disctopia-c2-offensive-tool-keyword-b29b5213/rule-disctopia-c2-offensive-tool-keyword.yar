rule rule_disctopia_c2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'disctopia-c2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "disctopia-c2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_disctopia_c2_offensive_tool_keyword = /\/disctopia\.py/ nocase ascii wide
                        $string2_disctopia_c2_offensive_tool_keyword = "/disctopia-c2" nocase ascii wide
                        $string3_disctopia_c2_offensive_tool_keyword = "/distopia-test" nocase ascii wide
                        $string4_disctopia_c2_offensive_tool_keyword = "Disctopia Backdoor" nocase ascii wide
                        $string5_disctopia_c2_offensive_tool_keyword = /disctopia\-c2\.git/ nocase ascii wide
                        $string6_disctopia_c2_offensive_tool_keyword = /disctopia\-c2\-main\.zip/ nocase ascii wide
                        $string7_disctopia_c2_offensive_tool_keyword = /keylogger\.py/ nocase ascii wide
                        $string8_disctopia_c2_offensive_tool_keyword = /sandboxevasion\.py/ nocase ascii wide

    condition:
        any of them
}