rule rule_EDRSandblast_GodFault_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDRSandblast-GodFault' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSandblast-GodFault"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDRSandblast_GodFault_offensive_tool_keyword = " Configuring Windows Firewall rules to block EDR network access" nocase ascii wide
                        $string2_EDRSandblast_GodFault_offensive_tool_keyword = /\s\-\-unhook\-method\s.{0,1000}\s\-\-dont\-unload\-driver\s.{0,1000}\s\-\-dump\-output\s/ nocase ascii wide
                        $string3_EDRSandblast_GodFault_offensive_tool_keyword = "/EDRSandblast/" nocase ascii wide
                        $string4_EDRSandblast_GodFault_offensive_tool_keyword = /\/LSASSProtectionBypass\/CredGuard\.c/ nocase ascii wide
                        $string5_EDRSandblast_GodFault_offensive_tool_keyword = /\/UserlandBypass\/.{0,1000}\.c/ nocase ascii wide
                        $string6_EDRSandblast_GodFault_offensive_tool_keyword = /\\LSASSProtectionBypass\\/ nocase ascii wide
                        $string7_EDRSandblast_GodFault_offensive_tool_keyword = /\\NtoskrnlOffsets\.csv/ nocase ascii wide
                        $string8_EDRSandblast_GodFault_offensive_tool_keyword = /\\WdigestOffsets\.csv/ nocase ascii wide
                        $string9_EDRSandblast_GodFault_offensive_tool_keyword = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" nocase ascii wide
                        $string10_EDRSandblast_GodFault_offensive_tool_keyword = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" nocase ascii wide
                        $string11_EDRSandblast_GodFault_offensive_tool_keyword = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" nocase ascii wide
                        $string12_EDRSandblast_GodFault_offensive_tool_keyword = "All EDR drivers were successfully removed from Kernel callbacks!" nocase ascii wide
                        $string13_EDRSandblast_GodFault_offensive_tool_keyword = "and Credential Guard will not be bypassed" nocase ascii wide
                        $string14_EDRSandblast_GodFault_offensive_tool_keyword = /C\:\\temp\\tmp\.tmp/ nocase ascii wide
                        $string15_EDRSandblast_GodFault_offensive_tool_keyword = "Credential Guard bypass might fail if RunAsPPL is enabled" nocase ascii wide
                        $string16_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast\.exe/ nocase ascii wide
                        $string17_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandBlast\.h/ nocase ascii wide
                        $string18_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast\.sln/ nocase ascii wide
                        $string19_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast\.vcxproj/ nocase ascii wide
                        $string20_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast_API\.c/ nocase ascii wide
                        $string21_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast_API\.exe/ nocase ascii wide
                        $string22_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast_API\.h/ nocase ascii wide
                        $string23_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast_LsassDump\.c/ nocase ascii wide
                        $string24_EDRSandblast_GodFault_offensive_tool_keyword = /EDRSandblast_LsassDump\.exe/ nocase ascii wide
                        $string25_EDRSandblast_GodFault_offensive_tool_keyword = "EDRSandblast-GodFault" nocase ascii wide
                        $string26_EDRSandblast_GodFault_offensive_tool_keyword = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" nocase ascii wide
                        $string27_EDRSandblast_GodFault_offensive_tool_keyword = "LSASS dump might fail if RunAsPPL is enabled" nocase ascii wide

    condition:
        any of them
}