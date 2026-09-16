rule rule_Blank_Grabber_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Blank-Grabber' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Blank-Grabber"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Blank_Grabber_offensive_tool_keyword = /\sBlankOBF\.py/ nocase ascii wide
                        $string2_Blank_Grabber_offensive_tool_keyword = "/Blank%20Grabber/Extras/hash" nocase ascii wide
                        $string3_Blank_Grabber_offensive_tool_keyword = /\/Blank\.Grabber\.zip/ nocase ascii wide
                        $string4_Blank_Grabber_offensive_tool_keyword = "/Blank-Grabber#download" nocase ascii wide
                        $string5_Blank_Grabber_offensive_tool_keyword = /\/Blank\-Grabber\.git/ nocase ascii wide
                        $string6_Blank_Grabber_offensive_tool_keyword = /\/BlankOBF\.py/ nocase ascii wide
                        $string7_Blank_Grabber_offensive_tool_keyword = /\\Blank\.Grabber\.zip/ nocase ascii wide
                        $string8_Blank_Grabber_offensive_tool_keyword = /\\BlankOBF\.py/ nocase ascii wide
                        $string9_Blank_Grabber_offensive_tool_keyword = /\\rarreg\.key/ nocase ascii wide
                        $string10_Blank_Grabber_offensive_tool_keyword = "1e83e7eb564b39cd4d600a3b9a906a2b59bbae26320b15b5065638ad267cc3cb" nocase ascii wide
                        $string11_Blank_Grabber_offensive_tool_keyword = "5a0bd791d08f5f9871a1b2fa7f1aea81d0aeb90c7df95fe0534d3faac1847e74" nocase ascii wide
                        $string12_Blank_Grabber_offensive_tool_keyword = /\-\-add\-data\srarreg\.key/ nocase ascii wide
                        $string13_Blank_Grabber_offensive_tool_keyword = /Blank\sGrabber\s\[Builder\]\\"/ nocase ascii wide
                        $string14_Blank_Grabber_offensive_tool_keyword = /Blank\sGrabber\s\[Fake\sError\sBuilder\]\\"/ nocase ascii wide
                        $string15_Blank_Grabber_offensive_tool_keyword = /Blank\sGrabber\s\[File\sPumper\]\\"/ nocase ascii wide
                        $string16_Blank_Grabber_offensive_tool_keyword = "Blank-c/Blank-Grabber" nocase ascii wide
                        $string17_Blank_Grabber_offensive_tool_keyword = "c97df5d25ea1e9ed5b95606adc492cfb6d4fe97e2a538fcaef0ea66f1a239e64" nocase ascii wide
                        $string18_Blank_Grabber_offensive_tool_keyword = /Grabbed\sby\sBlank\sGrabber\s\|\s/ nocase ascii wide
                        $string19_Blank_Grabber_offensive_tool_keyword = "import BlankOBF" nocase ascii wide
                        $string20_Blank_Grabber_offensive_tool_keyword = "Injecting backdoor into discord" nocase ascii wide
                        $string21_Blank_Grabber_offensive_tool_keyword = "ping localhost -n 3 > NUL && del /A H /F " nocase ascii wide
                        $string22_Blank_Grabber_offensive_tool_keyword = /powershell\sGet\-ItemPropertyValue\s\-Path\s\{\}\:SOFTWARE\\\\Roblox\\\\RobloxStudioBrowser\\\\roblox\.com\s\-Name\s\.ROBLOSECURITY/ nocase ascii wide
                        $string23_Blank_Grabber_offensive_tool_keyword = /powershell\sGet\-ItemPropertyValue\s\-Path\s\'HKLM\:SOFTWARE\\\\Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\SoftwareProtectionPlatform\'\s\-Name\sBackupProductKeyDefault/ nocase ascii wide
                        $string24_Blank_Grabber_offensive_tool_keyword = "SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies" nocase ascii wide
                        $string25_Blank_Grabber_offensive_tool_keyword = "SELECT origin_url, username_value, password_value FROM logins" nocase ascii wide
                        $string26_Blank_Grabber_offensive_tool_keyword = "Stealer finished its work" nocase ascii wide
                        $string27_Blank_Grabber_offensive_tool_keyword = "Stealing browser data" nocase ascii wide
                        $string28_Blank_Grabber_offensive_tool_keyword = "Stealing crypto wallets" nocase ascii wide
                        $string29_Blank_Grabber_offensive_tool_keyword = "Stealing discord tokens" nocase ascii wide
                        $string30_Blank_Grabber_offensive_tool_keyword = "Stealing Epic session" nocase ascii wide
                        $string31_Blank_Grabber_offensive_tool_keyword = "Stealing Growtopia session" nocase ascii wide
                        $string32_Blank_Grabber_offensive_tool_keyword = "Stealing Minecraft related files" nocase ascii wide
                        $string33_Blank_Grabber_offensive_tool_keyword = "Stealing Roblox cookies" nocase ascii wide
                        $string34_Blank_Grabber_offensive_tool_keyword = "Stealing Steam session" nocase ascii wide
                        $string35_Blank_Grabber_offensive_tool_keyword = "Stealing system information" nocase ascii wide
                        $string36_Blank_Grabber_offensive_tool_keyword = "Stealing telegram sessions" nocase ascii wide
                        $string37_Blank_Grabber_offensive_tool_keyword = "Stealing Uplay session" nocase ascii wide
                        $string38_Blank_Grabber_offensive_tool_keyword = /Trying\sto\sbypass\sUAC\s\(Application\swill\srestart\)/ nocase ascii wide
                        $string39_Blank_Grabber_offensive_tool_keyword = "Trying to disable defender" nocase ascii wide
                        $string40_Blank_Grabber_offensive_tool_keyword = "Trying to exclude bound file from defender" nocase ascii wide
                        $string41_Blank_Grabber_offensive_tool_keyword = "Trying to exclude the file from Windows defender" nocase ascii wide

    condition:
        any of them
}