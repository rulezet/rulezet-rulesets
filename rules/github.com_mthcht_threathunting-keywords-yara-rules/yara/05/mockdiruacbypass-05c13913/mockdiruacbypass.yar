rule MockDirUACBypass
{
    meta:
        description = "Detection patterns for the tool 'MockDirUACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MockDirUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\[\+\]\sAttempting\sto\scall\sthe\starget\sEXE\sfrom\sthe\smock\sdirectory/ nocase ascii wide
                        $string2 = /\[\+\]\sCreating\smock\sdirectories/ nocase ascii wide
                        $string3 = /hijackDll.{0,1000}WINMM\.dll/ nocase ascii wide
                        $string4 = "MockDirUACBypass" nocase ascii wide

    condition:
        any of them
}