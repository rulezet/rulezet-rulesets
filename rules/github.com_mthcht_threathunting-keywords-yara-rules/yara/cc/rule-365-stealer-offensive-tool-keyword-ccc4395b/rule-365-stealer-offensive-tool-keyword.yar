rule rule__365_Stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '365-Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "365-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1__365_Stealer_offensive_tool_keyword = " 365-Stealer " nocase ascii wide
                        $string2__365_Stealer_offensive_tool_keyword = " --custom-steal" nocase ascii wide
                        $string3__365_Stealer_offensive_tool_keyword = " --custom-steal listusers" nocase ascii wide
                        $string4__365_Stealer_offensive_tool_keyword = " --custom-steal onedrive" nocase ascii wide
                        $string5__365_Stealer_offensive_tool_keyword = " --custom-steal onenote" nocase ascii wide
                        $string6__365_Stealer_offensive_tool_keyword = " --custom-steal outlook" nocase ascii wide
                        $string7__365_Stealer_offensive_tool_keyword = " Redirect Url After Stealing ==> " nocase ascii wide
                        $string8__365_Stealer_offensive_tool_keyword = /\/365\-Stealer\.git/ nocase ascii wide
                        $string9__365_Stealer_offensive_tool_keyword = /\[\!\]\sLooks\slike\sVictim\s.{0,1000}\sdoesn\'t\shave\soffice365\sLicence\!/ nocase ascii wide
                        $string10__365_Stealer_offensive_tool_keyword = /\[\!\]\sStealing\sprocesses\sdelayed\swith\s/ nocase ascii wide
                        $string11__365_Stealer_offensive_tool_keyword = /\[\!\]\sSwithed\sto\scustom\sstealing\.\s/ nocase ascii wide
                        $string12__365_Stealer_offensive_tool_keyword = /\[\+\]\sVictim\s.{0,1000}\shave\soffice365\sLicence\!/ nocase ascii wide
                        $string13__365_Stealer_offensive_tool_keyword = /365\-Stealer\.py/ nocase ascii wide
                        $string14__365_Stealer_offensive_tool_keyword = "365-Stealer-master" nocase ascii wide
                        $string15__365_Stealer_offensive_tool_keyword = "AlteredSecurity/365-Stealer" nocase ascii wide
                        $string16__365_Stealer_offensive_tool_keyword = /cscript\s\.\.\\\\temp\.vbs/ nocase ascii wide
                        $string17__365_Stealer_offensive_tool_keyword = "'Disable all http access logs'" nocase ascii wide
                        $string18__365_Stealer_offensive_tool_keyword = "'Host the Phising App'" nocase ascii wide
                        $string19__365_Stealer_offensive_tool_keyword = "MIIEowIBAAKCAQEAvZtOCbMyFKJN3n89nctTfYLSeiCTNG01rAFl06hMkobyzr0c" nocase ascii wide
                        $string20__365_Stealer_offensive_tool_keyword = "o365-Attack-Toolkit" nocase ascii wide

    condition:
        any of them
}