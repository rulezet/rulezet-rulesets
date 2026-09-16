rule gcat
{
    meta:
        description = "Detection patterns for the tool 'gcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -exec-shellcode " nocase ascii wide
                        $string2 = /\sgcat\.py\s\-/ nocase ascii wide
                        $string3 = /\/gcat\.git/ nocase ascii wide
                        $string4 = /\/gcat\.py/ nocase ascii wide
                        $string5 = "byt3bl33d3r/gcat" nocase ascii wide
                        $string6 = /gcat.{0,1000}implant\.py/ nocase ascii wide
                        $string7 = /gcat\.is\.the\.shit\@gmail\.com/ nocase ascii wide
                        $string8 = "-start-keylogger" nocase ascii wide
                        $string9 = "-stop-keylogger" nocase ascii wide

    condition:
        any of them
}