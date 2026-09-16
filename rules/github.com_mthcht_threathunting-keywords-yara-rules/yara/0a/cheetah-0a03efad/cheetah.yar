rule cheetah
{
    meta:
        description = "Detection patterns for the tool 'cheetah' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cheetah"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-p\spwd1\.list\spwd2\.list\s/ nocase ascii wide
                        $string2 = /\/big_shell_pwd\.7z/ nocase ascii wide
                        $string3 = /\/cheetah\.git/ nocase ascii wide
                        $string4 = /\/cheetah\.py/
                        $string5 = /\\big_shell_pwd\.7z/ nocase ascii wide
                        $string6 = /\\cheetah\.py/ nocase ascii wide
                        $string7 = /\\cheetah\-master\.zip/ nocase ascii wide
                        $string8 = "5a1f9b0e-9f7c-4673-bf16-4740707f41b7" nocase ascii wide
                        $string9 = /a\svery\sfast\sbrute\sforce\swebshell\spassword\stool\./ nocase ascii wide
                        $string10 = /cheetah\.py\s\-/ nocase ascii wide
                        $string11 = /git\sclone\s.{0,1000}\s\/tmp\/cheetah/ nocase ascii wide
                        $string12 = /http\:\/\/localhost\/shell\.jsp\?pwd\=System\.out\.println\(/ nocase ascii wide
                        $string13 = "run --rm -it xshuden/cheetah" nocase ascii wide
                        $string14 = "shmilylty/cheetah" nocase ascii wide
                        $string15 = /sunnyelf\/cheetah\/archive\/master\.zip/ nocase ascii wide
                        $string16 = /sunnyelf\[\@hackfun\.org\]/ nocase ascii wide

    condition:
        any of them
}