rule rule_killProcessPOC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'killProcessPOC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "killProcessPOC"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_killProcessPOC_greyware_tool_keyword = /\/killProcessPOC\.git/ nocase ascii wide
                        $string2_killProcessPOC_greyware_tool_keyword = /\\\\\\\\\.\\\\aswSP_ArPot0/ nocase ascii wide
                        $string3_killProcessPOC_greyware_tool_keyword = /\\\\\\\\\.\\\\aswSP_ArPot1/ nocase ascii wide
                        $string4_killProcessPOC_greyware_tool_keyword = /\\\\\\\\\.\\\\aswSP_ArPot2/ nocase ascii wide
                        $string5_killProcessPOC_greyware_tool_keyword = /\\\\\\\\\.\\\\aswSP_ArPot3/ nocase ascii wide
                        $string6_killProcessPOC_greyware_tool_keyword = /\\\\\\\\\.\\\\aswSP_Avar/ nocase ascii wide
                        $string7_killProcessPOC_greyware_tool_keyword = /\\killProcessPOC/ nocase ascii wide
                        $string8_killProcessPOC_greyware_tool_keyword = "55ab03a0f7e3ce2c13664db76e5e0b6768cb66d88971b6bc6caf577831a77a23" nocase ascii wide
                        $string9_killProcessPOC_greyware_tool_keyword = /sc\.exe\screate\saswSP_ArPot1/ nocase ascii wide
                        $string10_killProcessPOC_greyware_tool_keyword = /sc\.exe\screate\saswSP_ArPot2/ nocase ascii wide
                        $string11_killProcessPOC_greyware_tool_keyword = /sc\.exe\screate\saswSP_ArPot3/ nocase ascii wide
                        $string12_killProcessPOC_greyware_tool_keyword = /sc\.exe\screate\saswSP_ArPots/ nocase ascii wide
                        $string13_killProcessPOC_greyware_tool_keyword = /sc\.exe\sstart\saswSP_ArPot/ nocase ascii wide
                        $string14_killProcessPOC_greyware_tool_keyword = "timwhitez/killProcessPOC" nocase ascii wide

    condition:
        any of them
}