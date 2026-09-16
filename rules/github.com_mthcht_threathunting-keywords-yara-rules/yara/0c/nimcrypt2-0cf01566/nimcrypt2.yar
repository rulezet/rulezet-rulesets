rule Nimcrypt2
{
    meta:
        description = "Detection patterns for the tool 'Nimcrypt2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nimcrypt2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --get-syscallstub " nocase ascii wide
                        $string2 = /\s\-\-llvm\-obfuscator\s.{0,1000}\s/ nocase ascii wide
                        $string3 = "/Nimcrypt2" nocase ascii wide
                        $string4 = /GetSyscallStub\.nim/ nocase ascii wide
                        $string5 = "nimcrypt -" nocase ascii wide
                        $string6 = /nimcrypt\.nim/ nocase ascii wide
                        $string7 = /syscalls\.nim/ nocase ascii wide

    condition:
        any of them
}