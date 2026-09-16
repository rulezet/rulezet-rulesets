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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}