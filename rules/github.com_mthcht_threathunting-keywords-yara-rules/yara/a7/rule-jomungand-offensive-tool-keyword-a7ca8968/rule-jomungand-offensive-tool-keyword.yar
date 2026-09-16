rule rule_Jomungand_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Jomungand' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jomungand"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Jomungand_offensive_tool_keyword = "----- LOADLIBRARYA HOOK -----" nocase ascii wide
                        $string2_Jomungand_offensive_tool_keyword = "----- SLEEP HOOK -----" nocase ascii wide
                        $string3_Jomungand_offensive_tool_keyword = "----- VIRTUALALLOC HOOK -----" nocase ascii wide
                        $string4_Jomungand_offensive_tool_keyword = /\/Jomungand\.git/ nocase ascii wide
                        $string5_Jomungand_offensive_tool_keyword = /\/Jormungand\.sln/ nocase ascii wide
                        $string6_Jomungand_offensive_tool_keyword = /\[\!\]\sCan\'t\sremove\sthe\sHWBP\-Hook\sfor\sVirtualAlloc\s\!/ nocase ascii wide
                        $string7_Jomungand_offensive_tool_keyword = /\\Jormungand\.sln/ nocase ascii wide
                        $string8_Jomungand_offensive_tool_keyword = "88B40068-B3DB-4C2F-86F9-8EADC52CFE58" nocase ascii wide
                        $string9_Jomungand_offensive_tool_keyword = /Jomungand\\vstudio\-project/ nocase ascii wide
                        $string10_Jomungand_offensive_tool_keyword = "Jomungand-main" nocase ascii wide
                        $string11_Jomungand_offensive_tool_keyword = /Jormungand\.exe/ nocase ascii wide
                        $string12_Jomungand_offensive_tool_keyword = /Jormungand\.vcxproj/ nocase ascii wide
                        $string13_Jomungand_offensive_tool_keyword = "Redirect LoadLibraryA to LdrLoadDll with spoofed ret addr !" nocase ascii wide
                        $string14_Jomungand_offensive_tool_keyword = "RtlDallas/Jomungand" nocase ascii wide
                        $string15_Jomungand_offensive_tool_keyword = /Sleep\sfor\s.{0,1000}\sms.{0,1000}\sredirect\sto\sKrakenMask\s\!/ nocase ascii wide

    condition:
        any of them
}