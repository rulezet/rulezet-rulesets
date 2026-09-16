rule rule_PwDump7_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PwDump7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PwDump7"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PwDump7_offensive_tool_keyword = /\/pwdump7\.zip/ nocase ascii wide
                        $string2_PwDump7_offensive_tool_keyword = /\\pwdump7/ nocase ascii wide
                        $string3_PwDump7_offensive_tool_keyword = /\\pwdump7\.zip/ nocase ascii wide
                        $string4_PwDump7_offensive_tool_keyword = "b20f667c2539954744ddcb7f1d673c2a6dc0c4a934df45a3cca15a203a661c88" nocase ascii wide
                        $string5_PwDump7_offensive_tool_keyword = "ee29e80a2e8c469655fe215eac14c2fbb201116e40fd056dcd1f602e1959263b" nocase ascii wide
                        $string6_PwDump7_offensive_tool_keyword = /Pwdump\sv7\.1\s\-\sraw\spassword\sextractor/ nocase ascii wide
                        $string7_PwDump7_offensive_tool_keyword = /PwDump7\.exe/ nocase ascii wide

    condition:
        any of them
}