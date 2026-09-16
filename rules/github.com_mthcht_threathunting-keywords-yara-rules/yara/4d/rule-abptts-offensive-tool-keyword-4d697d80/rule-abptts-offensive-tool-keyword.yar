rule rule_ABPTTS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ABPTTS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ABPTTS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ABPTTS_offensive_tool_keyword = /\/ABPTTS\.git/ nocase ascii wide
                        $string2_ABPTTS_offensive_tool_keyword = /\\ABPTTS\-master/ nocase ascii wide
                        $string3_ABPTTS_offensive_tool_keyword = /\=\=\=\[\[\[\sA\sBlack\sPath\sToward\sThe\sSun\s\]\]\]\=\=\=/ nocase ascii wide
                        $string4_ABPTTS_offensive_tool_keyword = "63688c4f211155c76f2948ba21ebaf83" nocase ascii wide
                        $string5_ABPTTS_offensive_tool_keyword = /abpttsclient\.py/ nocase ascii wide
                        $string6_ABPTTS_offensive_tool_keyword = /ABPTTSClient\-log\.txt/ nocase ascii wide
                        $string7_ABPTTS_offensive_tool_keyword = /abpttsfactory\.py/ nocase ascii wide
                        $string8_ABPTTS_offensive_tool_keyword = "Building ABPTTS configuration " nocase ascii wide
                        $string9_ABPTTS_offensive_tool_keyword = "nccgroup/ABPTTS" nocase ascii wide
                        $string10_ABPTTS_offensive_tool_keyword = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" nocase ascii wide

    condition:
        any of them
}