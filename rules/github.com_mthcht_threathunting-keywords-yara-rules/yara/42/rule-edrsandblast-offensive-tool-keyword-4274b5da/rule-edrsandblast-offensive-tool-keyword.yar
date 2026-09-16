rule rule_EDRSandBlast_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDRSandBlast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSandBlast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDRSandBlast_offensive_tool_keyword = /\s\-\-nt\-offsets\s.{0,1000}\.csv/ nocase ascii wide
                        $string2_EDRSandBlast_offensive_tool_keyword = /\/EDRSandblast\.git/ nocase ascii wide
                        $string3_EDRSandBlast_offensive_tool_keyword = /\\ntdlol\.txt/ nocase ascii wide
                        $string4_EDRSandBlast_offensive_tool_keyword = "04DFB6E4-809E-4C35-88A1-2CC5F1EBFEBD" nocase ascii wide
                        $string5_EDRSandBlast_offensive_tool_keyword = "3A2FCB56-01A3-41B3-BDAA-B25F45784B23" nocase ascii wide
                        $string6_EDRSandBlast_offensive_tool_keyword = "7E3E2ECE-D1EB-43C6-8C83-B52B7571954B" nocase ascii wide
                        $string7_EDRSandBlast_offensive_tool_keyword = /EDRSandblast\.c/ nocase ascii wide
                        $string8_EDRSandBlast_offensive_tool_keyword = /EDRSandblast\.exe/ nocase ascii wide
                        $string9_EDRSandBlast_offensive_tool_keyword = /EDRSandblast\.sln/ nocase ascii wide
                        $string10_EDRSandBlast_offensive_tool_keyword = "EDRSandblast_CLI" nocase ascii wide
                        $string11_EDRSandBlast_offensive_tool_keyword = "EDRSandblast_LsassDump" nocase ascii wide
                        $string12_EDRSandBlast_offensive_tool_keyword = "EDRSandblast_StaticLibrary" nocase ascii wide
                        $string13_EDRSandBlast_offensive_tool_keyword = "EDRSandblast-master" nocase ascii wide
                        $string14_EDRSandBlast_offensive_tool_keyword = "FFA0FDDE-BE70-49E4-97DE-753304EF1113" nocase ascii wide
                        $string15_EDRSandBlast_offensive_tool_keyword = /lsass\.exe.{0,1000}C\:\\temp\\tmp\.tmp/ nocase ascii wide
                        $string16_EDRSandBlast_offensive_tool_keyword = /LSASSProtectionBypass.{0,1000}\// nocase ascii wide
                        $string17_EDRSandBlast_offensive_tool_keyword = /NtoskrnlOffsets\.csv/ nocase ascii wide
                        $string18_EDRSandBlast_offensive_tool_keyword = "wavestone-cdt/EDRSandblast" nocase ascii wide
                        $string19_EDRSandBlast_offensive_tool_keyword = /\-\-wdigest\-offsets\s.{0,1000}\.csv\s/ nocase ascii wide
                        $string20_EDRSandBlast_offensive_tool_keyword = /WdigestOffsets\.csv/ nocase ascii wide

    condition:
        any of them
}