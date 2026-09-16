rule FakeCmdLine
{
    meta:
        description = "Detection patterns for the tool 'FakeCmdLine' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FakeCmdLine"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/FakeCmdLine" nocase ascii wide
                        $string2 = /\\FakeCmdLine/ nocase ascii wide
                        $string3 = "ExeToLaunch StringToBePutAsCmdline" nocase ascii wide
                        $string4 = /FakeCmdLine\./ nocase ascii wide

    condition:
        any of them
}