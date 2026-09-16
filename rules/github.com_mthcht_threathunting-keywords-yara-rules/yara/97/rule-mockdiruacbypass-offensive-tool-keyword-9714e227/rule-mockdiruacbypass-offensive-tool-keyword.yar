rule rule_MockDirUACBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MockDirUACBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MockDirUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_MockDirUACBypass_offensive_tool_keyword = /\[\+\]\sAttempting\sto\scall\sthe\starget\sEXE\sfrom\sthe\smock\sdirectory/ nocase ascii wide
                        $string2_MockDirUACBypass_offensive_tool_keyword = /\[\+\]\sCreating\smock\sdirectories/ nocase ascii wide
                        $string3_MockDirUACBypass_offensive_tool_keyword = /hijackDll.{0,1000}WINMM\.dll/ nocase ascii wide
                        $string4_MockDirUACBypass_offensive_tool_keyword = "MockDirUACBypass" nocase ascii wide

    condition:
        any of them
}