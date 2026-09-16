rule rule_SetProcessInjection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SetProcessInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetProcessInjection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SetProcessInjection_offensive_tool_keyword = /\/SetProcessInjection\.git/ nocase ascii wide
                        $string2_SetProcessInjection_offensive_tool_keyword = /\[\+\]\sYour\spayload\smust\sbe\sexecuted\snow\s\!/ nocase ascii wide
                        $string3_SetProcessInjection_offensive_tool_keyword = /\[x\]\sCannot\sload\sNTDLL\.DLL/ nocase ascii wide
                        $string4_SetProcessInjection_offensive_tool_keyword = "azfvgayqKwtFApcvyRedpUXculaeCCGA" nocase ascii wide
                        $string5_SetProcessInjection_offensive_tool_keyword = "CA280845-1F10-4E65-9DE7-D9C6513BBD91" nocase ascii wide
                        $string6_SetProcessInjection_offensive_tool_keyword = "OtterHacker/SetProcessInjection" nocase ascii wide
                        $string7_SetProcessInjection_offensive_tool_keyword = /payload\/encryptor_remote\.py/ nocase ascii wide
                        $string8_SetProcessInjection_offensive_tool_keyword = /SetProcessInjection.{0,1000}encryptor\.py/ nocase ascii wide
                        $string9_SetProcessInjection_offensive_tool_keyword = "SetProcessInjection-main" nocase ascii wide

    condition:
        any of them
}