rule rule_Nimcrypt2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nimcrypt2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nimcrypt2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Nimcrypt2_offensive_tool_keyword = " --get-syscallstub " nocase ascii wide
                        $string2_Nimcrypt2_offensive_tool_keyword = /\s\-\-llvm\-obfuscator\s.{0,1000}\s/ nocase ascii wide
                        $string3_Nimcrypt2_offensive_tool_keyword = "/Nimcrypt2" nocase ascii wide
                        $string4_Nimcrypt2_offensive_tool_keyword = /GetSyscallStub\.nim/ nocase ascii wide
                        $string5_Nimcrypt2_offensive_tool_keyword = "nimcrypt -" nocase ascii wide
                        $string6_Nimcrypt2_offensive_tool_keyword = /nimcrypt\.nim/ nocase ascii wide
                        $string7_Nimcrypt2_offensive_tool_keyword = /syscalls\.nim/ nocase ascii wide

    condition:
        any of them
}