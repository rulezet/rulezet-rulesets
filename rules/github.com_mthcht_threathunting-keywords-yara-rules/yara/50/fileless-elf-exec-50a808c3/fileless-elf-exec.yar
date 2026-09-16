rule fileless_elf_exec
{
    meta:
        description = "Detection patterns for the tool 'fileless-elf-exec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fileless-elf-exec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/fee\.py/
                        $string2 = /fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sperl/
                        $string3 = /fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sruby/
                        $string4 = /fee\s\-a\s.{0,1000}killall\ssshd.{0,1000}\s.{0,1000}busybox/
                        $string5 = /fee\s\-c\s.{0,1000}\/.{0,1000}\s\|\sssh\s.{0,1000}\@/
                        $string6 = /fee\s\-c\s.{0,1000}\/.{0,1000}\s\-w\s64\s\|\s/
                        $string7 = "fileless-elf-exec" nocase ascii wide
                        $string8 = "pip install --user fee"
                        $string9 = "pipx install fee"
                        $string10 = /python3\sfee\.py/

    condition:
        any of them
}