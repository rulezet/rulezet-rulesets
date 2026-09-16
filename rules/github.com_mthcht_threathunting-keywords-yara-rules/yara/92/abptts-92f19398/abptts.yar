rule ABPTTS
{
    meta:
        description = "Detection patterns for the tool 'ABPTTS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ABPTTS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/ABPTTS\.git/ nocase ascii wide
                        $string2 = /\\ABPTTS\-master/ nocase ascii wide
                        $string3 = /\=\=\=\[\[\[\sA\sBlack\sPath\sToward\sThe\sSun\s\]\]\]\=\=\=/ nocase ascii wide
                        $string4 = "63688c4f211155c76f2948ba21ebaf83" nocase ascii wide
                        $string5 = /abpttsclient\.py/ nocase ascii wide
                        $string6 = /ABPTTSClient\-log\.txt/ nocase ascii wide
                        $string7 = /abpttsfactory\.py/ nocase ascii wide
                        $string8 = "Building ABPTTS configuration " nocase ascii wide
                        $string9 = "nccgroup/ABPTTS" nocase ascii wide
                        $string10 = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" nocase ascii wide

    condition:
        any of them
}