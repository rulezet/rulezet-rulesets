rule Pateensy
{
    meta:
        description = "Detection patterns for the tool 'Pateensy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pateensy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/paensy\.cpp/ nocase ascii wide
                        $string2 = /BadUSB_AddAdmin\.ino/ nocase ascii wide
                        $string3 = /BadUSB_DownloadExecute\.ino/ nocase ascii wide
                        $string4 = /BadUSB_FacebookPost\.ino/ nocase ascii wide
                        $string5 = /BadUSB_HideWindow\.ino/ nocase ascii wide
                        $string6 = /BadUSB_LockYourComputer\.ino/ nocase ascii wide
                        $string7 = /Bye_Explorer\.ino/ nocase ascii wide
                        $string8 = "Pateensy/PaensyLib/" nocase ascii wide
                        $string9 = /powershell\-admin\-download\-execute\.ino/ nocase ascii wide
                        $string10 = "screetsec/Pateensy" nocase ascii wide
                        $string11 = /Teensypreter\.ino/ nocase ascii wide
                        $string12 = /WiFi_Hacker\.ino/ nocase ascii wide
                        $string13 = /Windows7\-BypassLogon\-Screen\.ino/ nocase ascii wide
                        $string14 = /windows\-forkbomb\.ino/ nocase ascii wide
                        $string15 = /You_spin_me__round\.ino/ nocase ascii wide

    condition:
        any of them
}