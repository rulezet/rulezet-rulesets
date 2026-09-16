rule rule_adfsbrute_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adfsbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfsbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_adfsbrute_offensive_tool_keyword = /\sadfsbrute\.py/ nocase ascii wide
                        $string2_adfsbrute_offensive_tool_keyword = " --tor_password " nocase ascii wide
                        $string3_adfsbrute_offensive_tool_keyword = " --userpassword_list " nocase ascii wide
                        $string4_adfsbrute_offensive_tool_keyword = /\/adfsbrute\.git/ nocase ascii wide
                        $string5_adfsbrute_offensive_tool_keyword = /\/adfsbrute\.py/ nocase ascii wide
                        $string6_adfsbrute_offensive_tool_keyword = /\\adfsbrute\.py/ nocase ascii wide
                        $string7_adfsbrute_offensive_tool_keyword = "d9adb9ecfa37595ce0dd2d8b4841334b32243bd30455fba4f59ce44a33efcdc4" nocase ascii wide
                        $string8_adfsbrute_offensive_tool_keyword = "ricardojoserf/adfsbrute" nocase ascii wide

    condition:
        any of them
}