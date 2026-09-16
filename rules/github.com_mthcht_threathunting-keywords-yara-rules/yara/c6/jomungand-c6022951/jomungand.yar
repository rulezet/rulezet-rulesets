rule Jomungand
{
    meta:
        description = "Detection patterns for the tool 'Jomungand' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jomungand"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "----- LOADLIBRARYA HOOK -----" nocase ascii wide
                        $string2 = "----- SLEEP HOOK -----" nocase ascii wide
                        $string3 = "----- VIRTUALALLOC HOOK -----" nocase ascii wide
                        $string4 = /\/Jomungand\.git/ nocase ascii wide
                        $string5 = /\/Jormungand\.sln/ nocase ascii wide
                        $string6 = /\[\!\]\sCan\'t\sremove\sthe\sHWBP\-Hook\sfor\sVirtualAlloc\s\!/ nocase ascii wide
                        $string7 = /\\Jormungand\.sln/ nocase ascii wide
                        $string8 = "88B40068-B3DB-4C2F-86F9-8EADC52CFE58" nocase ascii wide
                        $string9 = /Jomungand\\vstudio\-project/ nocase ascii wide
                        $string10 = "Jomungand-main" nocase ascii wide
                        $string11 = /Jormungand\.exe/ nocase ascii wide
                        $string12 = /Jormungand\.vcxproj/ nocase ascii wide
                        $string13 = "Redirect LoadLibraryA to LdrLoadDll with spoofed ret addr !" nocase ascii wide
                        $string14 = "RtlDallas/Jomungand" nocase ascii wide
                        $string15 = /Sleep\sfor\s.{0,1000}\sms.{0,1000}\sredirect\sto\sKrakenMask\s\!/ nocase ascii wide

    condition:
        any of them
}