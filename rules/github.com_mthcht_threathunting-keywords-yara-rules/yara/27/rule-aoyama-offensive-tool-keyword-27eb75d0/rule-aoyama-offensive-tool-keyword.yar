rule rule_Aoyama__offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Aoyama ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Aoyama "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Aoyama__offensive_tool_keyword = "#Code By Leeon123" nocase ascii wide
                        $string2_Aoyama__offensive_tool_keyword = /\[\!\]\sSetting\sUp\sC\&C\sModule/ nocase ascii wide
                        $string3_Aoyama__offensive_tool_keyword = /\[\!\]\sWelcom\sto\sthe\sAoyama\sC\&C\sServer/ nocase ascii wide
                        $string4_Aoyama__offensive_tool_keyword = "==> Python3 C&C server <==" nocase ascii wide
                        $string5_Aoyama__offensive_tool_keyword = "43f5ef8c625efba630bb99fd4ae086008ebed5c2f3386f1b43bbe8ee7c06f591" nocase ascii wide
                        $string6_Aoyama__offensive_tool_keyword = "Leeon123/Aoyama" nocase ascii wide
                        $string7_Aoyama__offensive_tool_keyword = "Leeon123/Python3-botnet" nocase ascii wide
                        $string8_Aoyama__offensive_tool_keyword = /python3\scnc\.py/ nocase ascii wide
                        $string9_Aoyama__offensive_tool_keyword = "rm -rf /bin/netstat"
                        $string10_Aoyama__offensive_tool_keyword = /rm\s\-rf\s\~\/\.bash_history/

    condition:
        any of them
}