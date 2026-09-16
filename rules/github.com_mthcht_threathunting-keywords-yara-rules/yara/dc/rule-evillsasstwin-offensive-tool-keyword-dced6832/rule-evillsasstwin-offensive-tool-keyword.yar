rule rule_EvilLsassTwin_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EvilLsassTwin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EvilLsassTwin"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EvilLsassTwin_offensive_tool_keyword = " EvilTwinServer " nocase ascii wide
                        $string2_EvilLsassTwin_offensive_tool_keyword = "/EvilLsassTwin" nocase ascii wide
                        $string3_EvilLsassTwin_offensive_tool_keyword = "/EvilLsassTwin/" nocase ascii wide
                        $string4_EvilLsassTwin_offensive_tool_keyword = "/EvilTwinServer" nocase ascii wide
                        $string5_EvilLsassTwin_offensive_tool_keyword = /\/malDll\.dll/ nocase ascii wide
                        $string6_EvilLsassTwin_offensive_tool_keyword = /\/Nimperiments\.git/ nocase ascii wide
                        $string7_EvilLsassTwin_offensive_tool_keyword = /\[\!\]\sInvalid\sExfil\sMethod\sChosen\!\sData\sWill\sNot\sBe\sSent\!/ nocase ascii wide
                        $string8_EvilLsassTwin_offensive_tool_keyword = /\[\+\]\sSucessfully\sDumped\sProcess\!/ nocase ascii wide
                        $string9_EvilLsassTwin_offensive_tool_keyword = /\[\+\]\sSuitable\sHandle\sto\sLSASS\sFound\sfrom\sPID\:\s/ nocase ascii wide
                        $string10_EvilLsassTwin_offensive_tool_keyword = /\\EvilLsassTwin\\/ nocase ascii wide
                        $string11_EvilLsassTwin_offensive_tool_keyword = /\\malDll\.dll/ nocase ascii wide
                        $string12_EvilLsassTwin_offensive_tool_keyword = /\\Nimperiments\-main/ nocase ascii wide
                        $string13_EvilLsassTwin_offensive_tool_keyword = "40408670ce1d814a3283a625566334fa191580622adbd23effa6e3cdaaafc5d5" nocase ascii wide
                        $string14_EvilLsassTwin_offensive_tool_keyword = "5c177feedd58a6ccc8287dee8c767dd486f2b5c55c234360be17f85fcbaa4501" nocase ascii wide
                        $string15_EvilLsassTwin_offensive_tool_keyword = /All\sgood\sin\sthe\shood\.\sCheck\sTemp\sfor\stest\.txt/ nocase ascii wide
                        $string16_EvilLsassTwin_offensive_tool_keyword = "Attempting Risky Operation: Opening Handle Directly to Lsass Process" nocase ascii wide
                        $string17_EvilLsassTwin_offensive_tool_keyword = "Build Evil Lsass Twin" nocase ascii wide
                        $string18_EvilLsassTwin_offensive_tool_keyword = "Building Evil Lsass Twin" nocase ascii wide
                        $string19_EvilLsassTwin_offensive_tool_keyword = /CreateFile\(\\"twin\.txt\\"/ nocase ascii wide
                        $string20_EvilLsassTwin_offensive_tool_keyword = /EvilLsassTwin\.exe/ nocase ascii wide
                        $string21_EvilLsassTwin_offensive_tool_keyword = /EvilLsassTwin\.exe/ nocase ascii wide
                        $string22_EvilLsassTwin_offensive_tool_keyword = /EvilLsassTwin\.nim/ nocase ascii wide
                        $string23_EvilLsassTwin_offensive_tool_keyword = /EvilLsassTwin\.nim/ nocase ascii wide
                        $string24_EvilLsassTwin_offensive_tool_keyword = /EvilTwin\.bin/ nocase ascii wide
                        $string25_EvilLsassTwin_offensive_tool_keyword = /EvilTwin\.dmp/ nocase ascii wide
                        $string26_EvilLsassTwin_offensive_tool_keyword = /EvilTwin\.dmp/ nocase ascii wide
                        $string27_EvilLsassTwin_offensive_tool_keyword = /EvilTwin\.dmp/ nocase ascii wide
                        $string28_EvilLsassTwin_offensive_tool_keyword = /EvilTwinServer\.nim/ nocase ascii wide
                        $string29_EvilLsassTwin_offensive_tool_keyword = /EvilTwinServer\.nim/ nocase ascii wide
                        $string30_EvilLsassTwin_offensive_tool_keyword = "f6e16eee3494ad168fa124552fba957ba8ddf8e7d96eedeef33f9e2afe1e9257" nocase ascii wide
                        $string31_EvilLsassTwin_offensive_tool_keyword = /from\shttps\:\/\/github\.com\/S3cur3Th1sSh1t\/Nim_Dinvoke/ nocase ascii wide
                        $string32_EvilLsassTwin_offensive_tool_keyword = /from\shttps\:\/\/www\.stevencampbell\.info\/Nim\-Convert\-Shellcode\-to\-UUID/ nocase ascii wide
                        $string33_EvilLsassTwin_offensive_tool_keyword = /http\:\/\/0hRIb4t1fWNPYBVA\.net\/index\.php/ nocase ascii wide
                        $string34_EvilLsassTwin_offensive_tool_keyword = "Lsass Dump File Created" nocase ascii wide
                        $string35_EvilLsassTwin_offensive_tool_keyword = /msfcallback\.bin/ nocase ascii wide
                        $string36_EvilLsassTwin_offensive_tool_keyword = /rastamouse\.me\/dumping\-lsass\-with\-duplicated\-handles/ nocase ascii wide
                        $string37_EvilLsassTwin_offensive_tool_keyword = "RePRGM/Nimperiments" nocase ascii wide
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