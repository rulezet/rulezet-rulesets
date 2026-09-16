rule rule_regreeper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'regreeper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regreeper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_regreeper_offensive_tool_keyword = /\/regreeper\.jpg/ nocase ascii wide
                        $string2_regreeper_offensive_tool_keyword = "/Reg-Restore-Persistence-Mole" nocase ascii wide
                        $string3_regreeper_offensive_tool_keyword = /\\save_reg\.hive/ nocase ascii wide
                        $string4_regreeper_offensive_tool_keyword = "A7AD39B5-9BA1-48A9-B928-CA25FDD8F31F" nocase ascii wide
                        $string5_regreeper_offensive_tool_keyword = /RegReeper\.7z/ nocase ascii wide
                        $string6_regreeper_offensive_tool_keyword = /RegReeper\.cpp/ nocase ascii wide
                        $string7_regreeper_offensive_tool_keyword = /RegReeper\.exe/ nocase ascii wide
                        $string8_regreeper_offensive_tool_keyword = /RegReeper\.sln/ nocase ascii wide
                        $string9_regreeper_offensive_tool_keyword = /RegReeper\.vcxproj/ nocase ascii wide
                        $string10_regreeper_offensive_tool_keyword = "Reg-Restore-Persistence-Mole-main" nocase ascii wide

    condition:
        any of them
}