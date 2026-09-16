rule rule_Throwback_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Throwback' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Throwback"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Throwback_offensive_tool_keyword = /\/Throwback\.git/ nocase ascii wide
                        $string2_Throwback_offensive_tool_keyword = "/ThrowbackDLL/" nocase ascii wide
                        $string3_Throwback_offensive_tool_keyword = /\\Throwback\.exe/ nocase ascii wide
                        $string4_Throwback_offensive_tool_keyword = /\\Throwback\\Throwback\.h/ nocase ascii wide
                        $string5_Throwback_offensive_tool_keyword = /\\ThrowbackDLL\\/ nocase ascii wide
                        $string6_Throwback_offensive_tool_keyword = /\\Throwback\-master\.zip/ nocase ascii wide
                        $string7_Throwback_offensive_tool_keyword = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
                        $string8_Throwback_offensive_tool_keyword = "60C1DA68-85AC-43AB-9A2B-27FA345EC113" nocase ascii wide
                        $string9_Throwback_offensive_tool_keyword = "D7D20588-8C18-4796-B2A4-386AECF14256" nocase ascii wide
                        $string10_Throwback_offensive_tool_keyword = "DLL_METASPLOIT_ATTACH" nocase ascii wide
                        $string11_Throwback_offensive_tool_keyword = /include\s\\"ThrowbackDLL\.h\\"/ nocase ascii wide
                        $string12_Throwback_offensive_tool_keyword = "silentbreaksec/Throwback" nocase ascii wide
                        $string13_Throwback_offensive_tool_keyword = /tbMangler\.py\sencode\s/ nocase ascii wide
                        $string14_Throwback_offensive_tool_keyword = /Throwback\\Base64_RC4\.h/ nocase ascii wide
                        $string15_Throwback_offensive_tool_keyword = /throwback_x64\.exe/ nocase ascii wide
                        $string16_Throwback_offensive_tool_keyword = /throwback_x86\.exe/ nocase ascii wide
                        $string17_Throwback_offensive_tool_keyword = /throwBackDev\.exe/ nocase ascii wide
                        $string18_Throwback_offensive_tool_keyword = /ThrowbackDLL\.cpp/ nocase ascii wide
                        $string19_Throwback_offensive_tool_keyword = /ThrowbackDLL\.exe/ nocase ascii wide
                        $string20_Throwback_offensive_tool_keyword = /ThrowbackDLL\.vcxproj/ nocase ascii wide
                        $string21_Throwback_offensive_tool_keyword = "ZAQwsxcde321" nocase ascii wide

    condition:
        any of them
}