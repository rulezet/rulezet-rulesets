rule rule_Pateensy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pateensy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pateensy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Pateensy_offensive_tool_keyword = /\/paensy\.cpp/ nocase ascii wide
                        $string2_Pateensy_offensive_tool_keyword = /BadUSB_AddAdmin\.ino/ nocase ascii wide
                        $string3_Pateensy_offensive_tool_keyword = /BadUSB_DownloadExecute\.ino/ nocase ascii wide
                        $string4_Pateensy_offensive_tool_keyword = /BadUSB_FacebookPost\.ino/ nocase ascii wide
                        $string5_Pateensy_offensive_tool_keyword = /BadUSB_HideWindow\.ino/ nocase ascii wide
                        $string6_Pateensy_offensive_tool_keyword = /BadUSB_LockYourComputer\.ino/ nocase ascii wide
                        $string7_Pateensy_offensive_tool_keyword = /Bye_Explorer\.ino/ nocase ascii wide
                        $string8_Pateensy_offensive_tool_keyword = "Pateensy/PaensyLib/" nocase ascii wide
                        $string9_Pateensy_offensive_tool_keyword = /powershell\-admin\-download\-execute\.ino/ nocase ascii wide
                        $string10_Pateensy_offensive_tool_keyword = "screetsec/Pateensy" nocase ascii wide
                        $string11_Pateensy_offensive_tool_keyword = /Teensypreter\.ino/ nocase ascii wide
                        $string12_Pateensy_offensive_tool_keyword = /WiFi_Hacker\.ino/ nocase ascii wide
                        $string13_Pateensy_offensive_tool_keyword = /Windows7\-BypassLogon\-Screen\.ino/ nocase ascii wide
                        $string14_Pateensy_offensive_tool_keyword = /windows\-forkbomb\.ino/ nocase ascii wide
                        $string15_Pateensy_offensive_tool_keyword = /You_spin_me__round\.ino/ nocase ascii wide

    condition:
        any of them
}