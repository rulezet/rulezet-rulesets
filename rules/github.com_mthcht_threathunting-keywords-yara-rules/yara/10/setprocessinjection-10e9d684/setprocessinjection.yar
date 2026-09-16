rule SetProcessInjection
{
    meta:
        description = "Detection patterns for the tool 'SetProcessInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetProcessInjection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SetProcessInjection\.git/ nocase ascii wide
                        $string2 = /\[\+\]\sYour\spayload\smust\sbe\sexecuted\snow\s\!/ nocase ascii wide
                        $string3 = /\[x\]\sCannot\sload\sNTDLL\.DLL/ nocase ascii wide
                        $string4 = "azfvgayqKwtFApcvyRedpUXculaeCCGA" nocase ascii wide
                        $string5 = "CA280845-1F10-4E65-9DE7-D9C6513BBD91" nocase ascii wide
                        $string6 = "OtterHacker/SetProcessInjection" nocase ascii wide
                        $string7 = /payload\/encryptor_remote\.py/ nocase ascii wide
                        $string8 = /SetProcessInjection.{0,1000}encryptor\.py/ nocase ascii wide
                        $string9 = "SetProcessInjection-main" nocase ascii wide

    condition:
        any of them
}