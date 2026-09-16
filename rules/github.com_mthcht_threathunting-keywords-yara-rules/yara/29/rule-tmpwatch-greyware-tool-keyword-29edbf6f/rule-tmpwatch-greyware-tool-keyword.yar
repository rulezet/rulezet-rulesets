rule rule_tmpwatch_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tmpwatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpwatch"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tmpwatch_greyware_tool_keyword = /chmod\s4777\s\/tmp\/\.scsi\/dev\/bin\/gsh/
                        $string2_tmpwatch_greyware_tool_keyword = /chown\sroot\:root\s\/tmp\/\.scsi\/dev\/bin\//
                        $string3_tmpwatch_greyware_tool_keyword = /echo\s.{0,1000}bailing\.\stry\sa\sdifferent\sname\\/ nocase ascii wide
                        $string4_tmpwatch_greyware_tool_keyword = /if\s\[\s\-f\s\/tmp\/tmpwatch\s\]\s.{0,1000}\sthen/ nocase ascii wide

    condition:
        any of them
}