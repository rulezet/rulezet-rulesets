rule rule_DriverDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DriverDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DriverDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DriverDump_offensive_tool_keyword = /\/DriverDump\.exe/ nocase ascii wide
                        $string2_DriverDump_offensive_tool_keyword = "/POC/driverdump/" nocase ascii wide
                        $string3_DriverDump_offensive_tool_keyword = /\\DriverDump\.c/ nocase ascii wide
                        $string4_DriverDump_offensive_tool_keyword = /\\DriverDump\.exe/ nocase ascii wide
                        $string5_DriverDump_offensive_tool_keyword = /\\DriverDump\.sln/ nocase ascii wide
                        $string6_DriverDump_offensive_tool_keyword = /\\DriverDump\.vcxproj/ nocase ascii wide
                        $string7_DriverDump_offensive_tool_keyword = /\\nanodump\.c/ nocase ascii wide
                        $string8_DriverDump_offensive_tool_keyword = "4f3632bb0c4eb05c443535dd3a773f83b3ac47f20ba75fbc3a2c8e6b80a46c60" nocase ascii wide
                        $string9_DriverDump_offensive_tool_keyword = "5b3811e463d5b424593910cbf7fd06218e993f8399a9add27b053f98bc984587" nocase ascii wide
                        $string10_DriverDump_offensive_tool_keyword = "7f005c1ea9c2021b5db5807fdf9e8e9f502b28f089ff17dc85b7d480a3e3d143" nocase ascii wide
                        $string11_DriverDump_offensive_tool_keyword = "83DF0D0B-8FC6-4BCA-9982-4D26523515A2" nocase ascii wide
                        $string12_DriverDump_offensive_tool_keyword = "c7600f446daa53037a63ad765e0873a9c45adfd8944e5fee1c1586936ecf2928" nocase ascii wide
                        $string13_DriverDump_offensive_tool_keyword = "Data Name=\"ServiceName\">procexp</Data>" nocase ascii wide
                        $string14_DriverDump_offensive_tool_keyword = "L\"NanoDumpPwd\"" nocase ascii wide
                        $string15_DriverDump_offensive_tool_keyword = "NanoDumpPPLmedicPipe" nocase ascii wide
                        $string16_DriverDump_offensive_tool_keyword = "NanoDumpSSPPipe" nocase ascii wide
                        $string17_DriverDump_offensive_tool_keyword = "pypykatz lsa minidump" nocase ascii wide
                        $string18_DriverDump_offensive_tool_keyword = /SYSTEM\\CurrentControlSet\\Services\\procexp/ nocase ascii wide
                        $string19_DriverDump_offensive_tool_keyword = "The nanodump was created succesfully" nocase ascii wide

    condition:
        any of them
}