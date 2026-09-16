rule SimpleNTSyscallFuzzer
{
    meta:
        description = "Detection patterns for the tool 'SimpleNTSyscallFuzzer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SimpleNTSyscallFuzzer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SimpleNTSyscallFuzzer\.git/ nocase ascii wide
                        $string2 = "FB351327-0816-448B-8FB7-63B550D6C808" nocase ascii wide
                        $string3 = /SimpleNtSyscallFuzzer\.v11\.suo/ nocase ascii wide
                        $string4 = /SimpleNTSyscallFuzzer\-main\\/ nocase ascii wide
                        $string5 = "waleedassar/SimpleNTSyscallFuzzer" nocase ascii wide

    condition:
        any of them
}