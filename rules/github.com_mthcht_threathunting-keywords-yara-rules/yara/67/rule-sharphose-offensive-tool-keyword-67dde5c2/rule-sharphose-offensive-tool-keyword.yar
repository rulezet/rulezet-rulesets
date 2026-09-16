rule rule_SharpHose_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpHose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpHose"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpHose_offensive_tool_keyword = " --action SPRAY_USERS " nocase ascii wide
                        $string2_SharpHose_offensive_tool_keyword = /\sSharpHose\.exe/ nocase ascii wide
                        $string3_SharpHose_offensive_tool_keyword = " --spraypassword " nocase ascii wide
                        $string4_SharpHose_offensive_tool_keyword = /\/SharpHose\.exe/ nocase ascii wide
                        $string5_SharpHose_offensive_tool_keyword = /\\SharpHose\.exe/ nocase ascii wide
                        $string6_SharpHose_offensive_tool_keyword = /\\SharpHose\\Program\.cs/ nocase ascii wide
                        $string7_SharpHose_offensive_tool_keyword = "29d30b556932d0657f14a0b290ec79d23f88d8454ca27151c8348ab7e4be9657" nocase ascii wide
                        $string8_SharpHose_offensive_tool_keyword = "51C6E016-1428-441D-82E9-BB0EB599BBC8" nocase ascii wide

    condition:
        any of them
}