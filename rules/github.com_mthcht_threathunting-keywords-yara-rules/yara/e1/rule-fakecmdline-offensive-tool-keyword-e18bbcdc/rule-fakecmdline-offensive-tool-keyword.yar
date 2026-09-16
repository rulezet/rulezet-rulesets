rule rule_FakeCmdLine_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FakeCmdLine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FakeCmdLine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FakeCmdLine_offensive_tool_keyword = "/FakeCmdLine" nocase ascii wide
                        $string2_FakeCmdLine_offensive_tool_keyword = /\\FakeCmdLine/ nocase ascii wide
                        $string3_FakeCmdLine_offensive_tool_keyword = "ExeToLaunch StringToBePutAsCmdline" nocase ascii wide
                        $string4_FakeCmdLine_offensive_tool_keyword = /FakeCmdLine\./ nocase ascii wide

    condition:
        any of them
}