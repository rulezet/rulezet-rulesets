rule rule_ETW_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ETW' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETW"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ETW_offensive_tool_keyword = /\$env\:COMPlus_ETWEnabled\=0/ nocase ascii wide
                        $string2_ETW_offensive_tool_keyword = /COMPlus_ETWEnabled\=0\\0\\0\\0/ nocase ascii wide
                        $string3_ETW_offensive_tool_keyword = /env_var_spoofing_poc\.cpp/ nocase ascii wide
                        $string4_ETW_offensive_tool_keyword = "set COMPlus_ETWEnabled=0" nocase ascii wide

    condition:
        any of them
}