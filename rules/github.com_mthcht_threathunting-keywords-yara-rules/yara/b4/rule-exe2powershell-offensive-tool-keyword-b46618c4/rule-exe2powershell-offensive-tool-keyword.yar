rule rule_exe2powershell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'exe2powershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exe2powershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_exe2powershell_offensive_tool_keyword = "/exe2powershell" nocase ascii wide
                        $string2_exe2powershell_offensive_tool_keyword = /exe2bat\.cpp/ nocase ascii wide
                        $string3_exe2powershell_offensive_tool_keyword = /exe2bat\.exe/ nocase ascii wide
                        $string4_exe2powershell_offensive_tool_keyword = /exe2powershell\.cpp/ nocase ascii wide
                        $string5_exe2powershell_offensive_tool_keyword = /exe2powershell\.exe/ nocase ascii wide
                        $string6_exe2powershell_offensive_tool_keyword = "exe2powershell-master" nocase ascii wide

    condition:
        any of them
}