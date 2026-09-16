rule rule_SimpleNTSyscallFuzzer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SimpleNTSyscallFuzzer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleNTSyscallFuzzer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SimpleNTSyscallFuzzer_offensive_tool_keyword = /\/SimpleNTSyscallFuzzer\.git/ nocase ascii wide
                        $string2_SimpleNTSyscallFuzzer_offensive_tool_keyword = "FB351327-0816-448B-8FB7-63B550D6C808" nocase ascii wide
                        $string3_SimpleNTSyscallFuzzer_offensive_tool_keyword = /SimpleNtSyscallFuzzer\.v11\.suo/ nocase ascii wide
                        $string4_SimpleNTSyscallFuzzer_offensive_tool_keyword = /SimpleNTSyscallFuzzer\-main\\/ nocase ascii wide
                        $string5_SimpleNTSyscallFuzzer_offensive_tool_keyword = "waleedassar/SimpleNTSyscallFuzzer" nocase ascii wide

    condition:
        any of them
}