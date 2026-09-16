rule rule_link_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'link' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "link"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_link_offensive_tool_keyword = /\skali\-install\.sh/ nocase ascii wide
                        $string2_link_offensive_tool_keyword = /\.\/kali\-install\.sh/
                        $string3_link_offensive_tool_keyword = /\.link\/links\/windows\/target\/x86_64\-pc\-windows\-gnu\/release\/link\.exe/ nocase ascii wide
                        $string4_link_offensive_tool_keyword = /\/\.link\/3rdparty\/SharpCollection/ nocase ascii wide
                        $string5_link_offensive_tool_keyword = /\/Stracciatella\/releases\/latest\/download\/Stracciatella\.exe/ nocase ascii wide
                        $string6_link_offensive_tool_keyword = /\\kali\-install\.sh/ nocase ascii wide
                        $string7_link_offensive_tool_keyword = /\\src\\links\\windows\\src\\evasion\.rs/ nocase ascii wide
                        $string8_link_offensive_tool_keyword = /execute\sPowerShell\swithout\spowershell\.exe/ nocase ascii wide
                        $string9_link_offensive_tool_keyword = /execute\-assembly\ssvchost\s.{0,100}\.exe/ nocase ascii wide
                        $string10_link_offensive_tool_keyword = /execute\-pe\ssvchost\swhoami\.exe/ nocase ascii wide
                        $string11_link_offensive_tool_keyword = /github\.com\/postrequest\/link/ nocase ascii wide
                        $string12_link_offensive_tool_keyword = /link\-inject.{0,100}inject\slink\sinto\sprocess/ nocase ascii wide
                        $string13_link_offensive_tool_keyword = /Out\-Minidump\.ps1/ nocase ascii wide
                        $string14_link_offensive_tool_keyword = /output\:\slink\.bin/ nocase ascii wide
                        $string15_link_offensive_tool_keyword = /output\:\slink\.dll/ nocase ascii wide
                        $string16_link_offensive_tool_keyword = "pip3 install pypykatz" nocase ascii wide
                        $string17_link_offensive_tool_keyword = /postrequest\/link\.git/ nocase ascii wide
                        $string18_link_offensive_tool_keyword = "pypykatz not installed" nocase ascii wide
                        $string19_link_offensive_tool_keyword = "sharp ADCollector" nocase ascii wide
                        $string20_link_offensive_tool_keyword = "sharp ADSearch" nocase ascii wide
                        $string21_link_offensive_tool_keyword = "sharp BetterSafetyKatz" nocase ascii wide
                        $string22_link_offensive_tool_keyword = "sharp init  download/update SharpCollection tools" nocase ascii wide
                        $string23_link_offensive_tool_keyword = "sharp InveighZero" nocase ascii wide
                        $string24_link_offensive_tool_keyword = "sharp SharpAllowedToAct" nocase ascii wide
                        $string25_link_offensive_tool_keyword = "sharp SharpAppLocker" nocase ascii wide
                        $string26_link_offensive_tool_keyword = "sharp SharpChisel" nocase ascii wide
                        $string27_link_offensive_tool_keyword = "sharp SharpChromium" nocase ascii wide
                        $string28_link_offensive_tool_keyword = "sharp SharpCrashEventLog " nocase ascii wide
                        $string29_link_offensive_tool_keyword = "sharp SharpKatz --Command logonpasswords" nocase ascii wide
                        $string30_link_offensive_tool_keyword = "sharp SharpMiniDump" nocase ascii wide
                        $string31_link_offensive_tool_keyword = "sharp Sharp-SMBExec " nocase ascii wide
                        $string32_link_offensive_tool_keyword = "sharp SharpSpray" nocase ascii wide
                        $string33_link_offensive_tool_keyword = "sharp SharpZeroLogon" nocase ascii wide
                        $string34_link_offensive_tool_keyword = "sharp StickyNotesExtract" nocase ascii wide
                        $string35_link_offensive_tool_keyword = "sharp winPEAS" nocase ascii wide
                        $string36_link_offensive_tool_keyword = /sharp_collection\.insert\(/ nocase ascii wide
                        $string37_link_offensive_tool_keyword = /SharpKatz\.exe/ nocase ascii wide
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