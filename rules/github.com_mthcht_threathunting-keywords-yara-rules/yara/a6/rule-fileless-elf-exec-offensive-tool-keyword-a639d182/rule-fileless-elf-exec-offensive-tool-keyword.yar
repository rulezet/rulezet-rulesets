rule rule_fileless_elf_exec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fileless-elf-exec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fileless-elf-exec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fileless_elf_exec_offensive_tool_keyword = /\.\/fee\.py/
                        $string2_fileless_elf_exec_offensive_tool_keyword = /fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sperl/
                        $string3_fileless_elf_exec_offensive_tool_keyword = /fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sruby/
                        $string4_fileless_elf_exec_offensive_tool_keyword = /fee\s\-a\s.{0,1000}killall\ssshd.{0,1000}\s.{0,1000}busybox/
                        $string5_fileless_elf_exec_offensive_tool_keyword = /fee\s\-c\s.{0,1000}\/.{0,1000}\s\|\sssh\s.{0,1000}\@/
                        $string6_fileless_elf_exec_offensive_tool_keyword = /fee\s\-c\s.{0,1000}\/.{0,1000}\s\-w\s64\s\|\s/
                        $string7_fileless_elf_exec_offensive_tool_keyword = "fileless-elf-exec" nocase ascii wide
                        $string8_fileless_elf_exec_offensive_tool_keyword = "pip install --user fee"
                        $string9_fileless_elf_exec_offensive_tool_keyword = "pipx install fee"
                        $string10_fileless_elf_exec_offensive_tool_keyword = /python3\sfee\.py/

    condition:
        any of them
}