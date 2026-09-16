rule rule_pwnlook_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pwnlook' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwnlook"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pwnlook_offensive_tool_keyword = /\\"\!\!Something\swent\swrong\.\sMaybe\sOutlook\sis\snot\srunning\.\\"/ nocase ascii wide
                        $string2_pwnlook_offensive_tool_keyword = /\/pwnlook\.exe/ nocase ascii wide
                        $string3_pwnlook_offensive_tool_keyword = /\/pwnlook\.git/ nocase ascii wide
                        $string4_pwnlook_offensive_tool_keyword = "/pwnlook/releases/download/" nocase ascii wide
                        $string5_pwnlook_offensive_tool_keyword = /\/pwnlook35\.exe/ nocase ascii wide
                        $string6_pwnlook_offensive_tool_keyword = /\/pwnlook481\.exe/ nocase ascii wide
                        $string7_pwnlook_offensive_tool_keyword = /\\pwnlook\.exe/ nocase ascii wide
                        $string8_pwnlook_offensive_tool_keyword = /\\pwnlook35\.exe/ nocase ascii wide
                        $string9_pwnlook_offensive_tool_keyword = /\\pwnlook481\.exe/ nocase ascii wide
                        $string10_pwnlook_offensive_tool_keyword = ">pwnlook35<" nocase ascii wide
                        $string11_pwnlook_offensive_tool_keyword = "09aa42564f461b40c5d610872ad6939f8dc31f9bc88be7b9604845fb61be5176" nocase ascii wide
                        $string12_pwnlook_offensive_tool_keyword = "09aa42564f461b40c5d610872ad6939f8dc31f9bc88be7b9604845fb61be5176" nocase ascii wide
                        $string13_pwnlook_offensive_tool_keyword = "1642e74e1c5dfd2863c2100b241e1f4897180a5aba2dd7313060c7953b24f105" nocase ascii wide
                        $string14_pwnlook_offensive_tool_keyword = "2709ef4de6f00a57c05cf4a39228cf87fa522abe20318aa4a09b34ba6cf7eea2" nocase ascii wide
                        $string15_pwnlook_offensive_tool_keyword = "58f9c5248fa5a9cc64622cc12e3963690eed691cd16cbdf5506d5328cfb41f69" nocase ascii wide
                        $string16_pwnlook_offensive_tool_keyword = "5a7f1bf78dd911a486125a32312c46ddcf8ea6523498a49c7cbba44c25097028" nocase ascii wide
                        $string17_pwnlook_offensive_tool_keyword = "67aa975f27ff2c5b874c62c9665c345e54c9dedecacf8b8439d6e30b86906350" nocase ascii wide
                        $string18_pwnlook_offensive_tool_keyword = "6D663511-76E4-4D74-9B3E-191E1471C4EF" nocase ascii wide
                        $string19_pwnlook_offensive_tool_keyword = "9e6659ea06490dde8a0815c3df51dfa242e6f9f0dd8f5a3ba3e7e4cdc2e77630" nocase ascii wide
                        $string20_pwnlook_offensive_tool_keyword = "amjcyber/pwnlook" nocase ascii wide
                        $string21_pwnlook_offensive_tool_keyword = "d3423d953de70480415b1bb516c2a5c635cf2c78a531cc5e4afce3ab11725e90" nocase ascii wide
                        $string22_pwnlook_offensive_tool_keyword = "e8a017f717909f20e325d901af37d25b1e19e363923dfe61dfecae77d7d979ef" nocase ascii wide
                        $string23_pwnlook_offensive_tool_keyword = /pwnlook\.exe\s/ nocase ascii wide
                        $string24_pwnlook_offensive_tool_keyword = /pwnlook35\.exe\s/ nocase ascii wide
                        $string25_pwnlook_offensive_tool_keyword = /pwnlook481\.exe\s/ nocase ascii wide
                        $string26_pwnlook_offensive_tool_keyword = /regsvr32\.exe\s\.\\Redemption\.dll/ nocase ascii wide
                        $string27_pwnlook_offensive_tool_keyword = /regsvr32\.exe\s\.\\Redemption64\.dll/ nocase ascii wide
                        $string28_pwnlook_offensive_tool_keyword = /regsvr32\.exe\s\-u\s\.\\Redemption\.dll/ nocase ascii wide
                        $string29_pwnlook_offensive_tool_keyword = /regsvr32\.exe\s\-u\s\.\\Redemption64\.dll/ nocase ascii wide
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