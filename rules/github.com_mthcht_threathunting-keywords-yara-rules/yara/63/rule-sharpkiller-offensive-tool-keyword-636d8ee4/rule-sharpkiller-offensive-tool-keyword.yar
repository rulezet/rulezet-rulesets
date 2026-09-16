rule rule_SharpKiller_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpKiller_offensive_tool_keyword = /\/SharpKiller\.git/ nocase ascii wide
                        $string2_SharpKiller_offensive_tool_keyword = /\/Sharp\-Killer\.sln/ nocase ascii wide
                        $string3_SharpKiller_offensive_tool_keyword = /\\AMSIPatcher\.cs/ nocase ascii wide
                        $string4_SharpKiller_offensive_tool_keyword = /\\Sharp\-Killer\.sln/ nocase ascii wide
                        $string5_SharpKiller_offensive_tool_keyword = "4DD3206C-F14A-43A3-8EA8-88676810B8CD" nocase ascii wide
                        $string6_SharpKiller_offensive_tool_keyword = "S1lkys/SharpKiller" nocase ascii wide
                        $string7_SharpKiller_offensive_tool_keyword = /Sharp\-Killer\.csproj/ nocase ascii wide
                        $string8_SharpKiller_offensive_tool_keyword = /Sharp\-Killer\.exe/ nocase ascii wide
                        $string9_SharpKiller_offensive_tool_keyword = /Sharp\-Killer\.pdb/ nocase ascii wide
                        $string10_SharpKiller_offensive_tool_keyword = "SharpKiller-main" nocase ascii wide

    condition:
        any of them
}