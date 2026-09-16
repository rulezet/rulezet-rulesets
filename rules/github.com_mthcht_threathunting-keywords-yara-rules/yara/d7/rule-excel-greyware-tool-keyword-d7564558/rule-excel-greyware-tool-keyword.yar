rule rule_Excel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Excel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Excel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Excel_greyware_tool_keyword = /reg\sadd\sHKCU\\software\\policies\\microsoft\\office\\16\.0\\excel\\security\s\/v\sPythonFunctionWarnings\s\/t\sREG_DWORD\s\/d\s0\s\/f\?/ nocase ascii wide
                        $string2_Excel_greyware_tool_keyword = /Set\-ItemProperty\s.{0,1000}\\excel\\security.{0,1000}pythonfunctionwarnings.{0,1000}0/ nocase ascii wide

    condition:
        any of them
}