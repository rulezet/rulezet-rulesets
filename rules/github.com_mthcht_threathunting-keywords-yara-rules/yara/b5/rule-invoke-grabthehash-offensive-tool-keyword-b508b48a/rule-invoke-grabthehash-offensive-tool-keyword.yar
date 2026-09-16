rule rule_Invoke_GrabTheHash_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-GrabTheHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-GrabTheHash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_GrabTheHash_offensive_tool_keyword = /\[\-\]\sDomain\sswitch\snot\sprovided\.\sEnumerating\sthe\sDomain\sName/ nocase ascii wide
                        $string2_Invoke_GrabTheHash_offensive_tool_keyword = /\[\-\]\sStopping\shere\,\sbefore\sgrabbing\sthe\sHash/ nocase ascii wide
                        $string3_Invoke_GrabTheHash_offensive_tool_keyword = "0592164ed8c8e6330431ba1f8a3eeee650af93d11b4320cfcfda75483b699c32" nocase ascii wide
                        $string4_Invoke_GrabTheHash_offensive_tool_keyword = "Invoke-GrabTheHash" nocase ascii wide

    condition:
        any of them
}