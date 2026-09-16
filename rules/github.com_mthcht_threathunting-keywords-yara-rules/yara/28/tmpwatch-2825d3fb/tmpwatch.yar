rule tmpwatch
{
    meta:
        description = "Detection patterns for the tool 'tmpwatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpwatch"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /chmod\s4777\s\/tmp\/\.scsi\/dev\/bin\/gsh/
                        $string2 = /chown\sroot\:root\s\/tmp\/\.scsi\/dev\/bin\//
                        $string3 = /echo\s.{0,1000}bailing\.\stry\sa\sdifferent\sname\\/ nocase ascii wide
                        $string4 = /if\s\[\s\-f\s\/tmp\/tmpwatch\s\]\s.{0,1000}\sthen/ nocase ascii wide

    condition:
        any of them
}