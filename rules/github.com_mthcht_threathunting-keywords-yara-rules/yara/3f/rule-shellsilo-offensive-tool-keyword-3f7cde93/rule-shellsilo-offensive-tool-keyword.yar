rule rule_shellsilo_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shellsilo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shellsilo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_shellsilo_offensive_tool_keyword = /\sshellsilo\.py/ nocase ascii wide
                        $string2_shellsilo_offensive_tool_keyword = /\/shellsilo\.git/ nocase ascii wide
                        $string3_shellsilo_offensive_tool_keyword = /\/shellsilo\.py/ nocase ascii wide
                        $string4_shellsilo_offensive_tool_keyword = /\\shellsilo\.py/ nocase ascii wide
                        $string5_shellsilo_offensive_tool_keyword = "05f9e54b0f6e0e143de11f98094e43643acaf17e01e0f7387388dc6d91681322" nocase ascii wide
                        $string6_shellsilo_offensive_tool_keyword = "nixpal/shellsilo" nocase ascii wide

    condition:
        any of them
}