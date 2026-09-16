rule rule_cheetah_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cheetah' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cheetah"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cheetah_offensive_tool_keyword = /\s\-p\spwd1\.list\spwd2\.list\s/ nocase ascii wide
                        $string2_cheetah_offensive_tool_keyword = /\/big_shell_pwd\.7z/ nocase ascii wide
                        $string3_cheetah_offensive_tool_keyword = /\/cheetah\.git/ nocase ascii wide
                        $string4_cheetah_offensive_tool_keyword = /\/cheetah\.py/
                        $string5_cheetah_offensive_tool_keyword = /\\big_shell_pwd\.7z/ nocase ascii wide
                        $string6_cheetah_offensive_tool_keyword = /\\cheetah\.py/ nocase ascii wide
                        $string7_cheetah_offensive_tool_keyword = /\\cheetah\-master\.zip/ nocase ascii wide
                        $string8_cheetah_offensive_tool_keyword = "5a1f9b0e-9f7c-4673-bf16-4740707f41b7" nocase ascii wide
                        $string9_cheetah_offensive_tool_keyword = /a\svery\sfast\sbrute\sforce\swebshell\spassword\stool\./ nocase ascii wide
                        $string10_cheetah_offensive_tool_keyword = /cheetah\.py\s\-/ nocase ascii wide
                        $string11_cheetah_offensive_tool_keyword = /git\sclone\s.{0,1000}\s\/tmp\/cheetah/ nocase ascii wide
                        $string12_cheetah_offensive_tool_keyword = /http\:\/\/localhost\/shell\.jsp\?pwd\=System\.out\.println\(/ nocase ascii wide
                        $string13_cheetah_offensive_tool_keyword = "run --rm -it xshuden/cheetah" nocase ascii wide
                        $string14_cheetah_offensive_tool_keyword = "shmilylty/cheetah" nocase ascii wide
                        $string15_cheetah_offensive_tool_keyword = /sunnyelf\/cheetah\/archive\/master\.zip/ nocase ascii wide
                        $string16_cheetah_offensive_tool_keyword = /sunnyelf\[\@hackfun\.org\]/ nocase ascii wide

    condition:
        any of them
}