rule rule_Payload_Download_Cradles_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Payload-Download-Cradles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Payload-Download-Cradles"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Payload_Download_Cradles_offensive_tool_keyword = " /c PoWErSheLl -nopROfi -EXe byPAsS -wiNDOwsTy HIDdEN -cOMMA " nocase ascii wide
                        $string2_Payload_Download_Cradles_offensive_tool_keyword = /\sCreateObject\(\\"W\\"\+\\"S\\"\+\\"cr\\"\+\\"ip\\"\+\\"t\.\\"\+\\"S\\"\+\\"h\\"\+\\"e\\"\+\\"l\\"\+\\"l\\"\)/ nocase ascii wide
                        $string3_Payload_Download_Cradles_offensive_tool_keyword = " danielbohannon/Invoke-CradleCrafter" nocase ascii wide
                        $string4_Payload_Download_Cradles_offensive_tool_keyword = /\sDownload_Cradles\.hta/ nocase ascii wide
                        $string5_Payload_Download_Cradles_offensive_tool_keyword = /\sDownload_Cradles\.ps1/ nocase ascii wide
                        $string6_Payload_Download_Cradles_offensive_tool_keyword = " -eXecut byPaSS -Noprof -w H -Co " nocase ascii wide
                        $string7_Payload_Download_Cradles_offensive_tool_keyword = /\s\-eXecUT\sbyPAss\s\-WINDo\s1\s\-nOpR\s\-coMm\s\\"\\"\&\s\(\(vARiaBlE\s\'.{0,100}mdr.{0,100}\'\)\.Name\[3\,11\,2\]\-JoiN\'\'\)/ nocase ascii wide
                        $string8_Payload_Download_Cradles_offensive_tool_keyword = " -eXecUT byPAss -WINDo 1 -nOpR -coMm " nocase ascii wide
                        $string9_Payload_Download_Cradles_offensive_tool_keyword = /\s\-NoP\s\-w\sHidDen\s\-c\s\$a\=neW\-ObJeCt\snET\.wEbClieNt/ nocase ascii wide
                        $string10_Payload_Download_Cradles_offensive_tool_keyword = " -nopROfi -EXe byPAsS -wiNDOwsTy HIDdEN -cOMMA " nocase ascii wide
                        $string11_Payload_Download_Cradles_offensive_tool_keyword = " -NopROFi -wIN hidd -EXEcutiOnPoLiC BYpAsS  -COm    " nocase ascii wide
                        $string12_Payload_Download_Cradles_offensive_tool_keyword = " -NoPRofi -WiNdoWSTYL hidd -EXecUTiOnPO BYpASS -cO " nocase ascii wide
                        $string13_Payload_Download_Cradles_offensive_tool_keyword = " -wINdOwstYL Hi -nop -eXecU BYpAss -COm  " nocase ascii wide
                        $string14_Payload_Download_Cradles_offensive_tool_keyword = /\$c\.Proxy\.Credentials\=\[Net\.CredentialCache\]\:\:DefaultCredentials\;\`i\`e\`x\s\$c\.downloadstring/ nocase ascii wide
                        $string15_Payload_Download_Cradles_offensive_tool_keyword = /\.\\\\"do\`wnLO\`ADS\`TRinG\\/ nocase ascii wide
                        $string16_Payload_Download_Cradles_offensive_tool_keyword = /\/Download\:Cradle\.js/ nocase ascii wide
                        $string17_Payload_Download_Cradles_offensive_tool_keyword = /\/Download_Cradles\.hta/ nocase ascii wide
                        $string18_Payload_Download_Cradles_offensive_tool_keyword = /\/Download_Cradles\.ps1/ nocase ascii wide
                        $string19_Payload_Download_Cradles_offensive_tool_keyword = /\/Download\-Cradles\.cmd/ nocase ascii wide
                        $string20_Payload_Download_Cradles_offensive_tool_keyword = /\/Payload\-Download\-Cradles\.git/ nocase ascii wide
                        $string21_Payload_Download_Cradles_offensive_tool_keyword = /\[System\.Windows\.Forms\.MessageBox\]\:\:Show\(\\"Congratulations\,\sit\slooks\slike\,\syour\sdownload\scradle\sis\sworking/ nocase ascii wide
                        $string22_Payload_Download_Cradles_offensive_tool_keyword = /\\Download\:Cradle\.js/ nocase ascii wide
                        $string23_Payload_Download_Cradles_offensive_tool_keyword = /\\Download_Cradles\.hta/ nocase ascii wide
                        $string24_Payload_Download_Cradles_offensive_tool_keyword = /\\Download_Cradles\.ps1/ nocase ascii wide
                        $string25_Payload_Download_Cradles_offensive_tool_keyword = /\\Download\-Cradles\.cmd/ nocase ascii wide
                        $string26_Payload_Download_Cradles_offensive_tool_keyword = "1ecb2406b796017446aa92b071d1f26f7fbf2a1a9c61f6b393437500518ec193" nocase ascii wide
                        $string27_Payload_Download_Cradles_offensive_tool_keyword = "61f31088bc43825c500d7d6f22dd7d259b56dd181c9a59650975bd5e9e91cb25" nocase ascii wide
                        $string28_Payload_Download_Cradles_offensive_tool_keyword = "a2be75dd7462fbb4753ae380a987351c51d6cd41ba5cc41f08242feeec1df06f" nocase ascii wide
                        $string29_Payload_Download_Cradles_offensive_tool_keyword = "b7b10a29015b41041519488dc632cd5b0b39358f56d388277d99304917be4a9d" nocase ascii wide
                        $string30_Payload_Download_Cradles_offensive_tool_keyword = /CreateObject\(\\"\\"W\\"\\"\+\\"\\"S\\"\\"\+\\"\\"cr\\"\\"\+\\"\\"ip\\"\\"\+\\"\\"t\.\\"\\"\+\\"\\"S\\"\\"\+\\"\\"h\\"\\"\+\\"\\"e\\"\\"\+\\"\\"l\\"\\"\+\\"\\"l\\"\\"/ nocase ascii wide
                        $string31_Payload_Download_Cradles_offensive_tool_keyword = /Download\:Cradle\.js/ nocase ascii wide
                        $string32_Payload_Download_Cradles_offensive_tool_keyword = /Download_Cradles\./ nocase ascii wide
                        $string33_Payload_Download_Cradles_offensive_tool_keyword = /Download\-Cradles\.cmd/ nocase ascii wide
                        $string34_Payload_Download_Cradles_offensive_tool_keyword = /hidd\s\-EXecUTiOnPO\sBYpASS\s\-cO\s\s\\"i\`EX\s\(\s\s\s\sneW\-o\`BJE\`cT\sN\`ET\.\`weBcl\`IeNT\s\s\s\s\)/ nocase ascii wide
                        $string35_Payload_Download_Cradles_offensive_tool_keyword = /https\:\/\/cutt\.ly\/syFzILH/ nocase ascii wide
                        $string36_Payload_Download_Cradles_offensive_tool_keyword = /https\:\/\/pastebin\.com\/raw\/88SGrHVh/ nocase ascii wide
                        $string37_Payload_Download_Cradles_offensive_tool_keyword = "Invoke-CradleCrafter " nocase ascii wide
                        $string38_Payload_Download_Cradles_offensive_tool_keyword = "Payload-Download-Cradles" nocase ascii wide
                        $string39_Payload_Download_Cradles_offensive_tool_keyword = /\'ps\'\+\'\:\'\+\'\/\'\+\'\/\'\+\'cutt\.ly\/syFzIL/ nocase ascii wide
                        $string40_Payload_Download_Cradles_offensive_tool_keyword = "VirtualAlllocEx/Payload-Download-Cradles" nocase ascii wide
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