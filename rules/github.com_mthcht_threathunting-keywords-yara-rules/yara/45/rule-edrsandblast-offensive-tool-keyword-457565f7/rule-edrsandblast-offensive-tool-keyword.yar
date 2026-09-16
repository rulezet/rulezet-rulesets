rule rule_EDRSandBlast_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EDRSandBlast' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EDRSandBlast"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EDRSandBlast_offensive_tool_keyword = /\s\-\-nt\-offsets\s.{0,100}\.csv/ nocase ascii wide
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
                        $string15_EDRSandBlast_offensive_tool_keyword = /lsass\.exe.{0,100}C\:\\temp\\tmp\.tmp/ nocase ascii wide
                        $string16_EDRSandBlast_offensive_tool_keyword = /LSASSProtectionBypass.{0,100}\// nocase ascii wide
                        $string17_EDRSandBlast_offensive_tool_keyword = /NtoskrnlOffsets\.csv/ nocase ascii wide
                        $string18_EDRSandBlast_offensive_tool_keyword = "wavestone-cdt/EDRSandblast" nocase ascii wide
                        $string19_EDRSandBlast_offensive_tool_keyword = /\-\-wdigest\-offsets\s.{0,100}\.csv\s/ nocase ascii wide
                        $string20_EDRSandBlast_offensive_tool_keyword = /WdigestOffsets\.csv/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}