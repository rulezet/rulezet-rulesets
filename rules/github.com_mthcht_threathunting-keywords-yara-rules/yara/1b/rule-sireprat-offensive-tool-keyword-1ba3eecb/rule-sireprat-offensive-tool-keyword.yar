rule rule_SirepRAT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SirepRAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SirepRAT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SirepRAT_offensive_tool_keyword = " --return_output --as_logged_on_user --cmd " nocase ascii wide
                        $string2_SirepRAT_offensive_tool_keyword = /\sSirepRAT\.py/ nocase ascii wide
                        $string3_SirepRAT_offensive_tool_keyword = /\/Sirep_Command_Payload\.bt/ nocase ascii wide
                        $string4_SirepRAT_offensive_tool_keyword = /\/SirepRAT\.git/ nocase ascii wide
                        $string5_SirepRAT_offensive_tool_keyword = /\/SirepRAT\.py/ nocase ascii wide
                        $string6_SirepRAT_offensive_tool_keyword = "/SirepRAT/releases/" nocase ascii wide
                        $string7_SirepRAT_offensive_tool_keyword = /\\Sirep_Command_Payload\.bt/ nocase ascii wide
                        $string8_SirepRAT_offensive_tool_keyword = /\\SirepRAT\.py/ nocase ascii wide
                        $string9_SirepRAT_offensive_tool_keyword = /\\SirepRAT\\/ nocase ascii wide
                        $string10_SirepRAT_offensive_tool_keyword = /\\SirepRAT\-2\.0\.0\\/ nocase ascii wide
                        $string11_SirepRAT_offensive_tool_keyword = /\\SirepRAT\-master/ nocase ascii wide
                        $string12_SirepRAT_offensive_tool_keyword = /\\Windows\\System32\\uploaded\.txt/ nocase ascii wide
                        $string13_SirepRAT_offensive_tool_keyword = "029fa62f9ee4ffbf98d5b187c658db8ecff38ccdc4dc5a8c37890446a33d1a23" nocase ascii wide
                        $string14_SirepRAT_offensive_tool_keyword = "4156a612622946b1daab4b43c632edf80477c45f2bbf55f474ffc33c1cd077f2" nocase ascii wide
                        $string15_SirepRAT_offensive_tool_keyword = "845e930b1479640235d571dceb63d0b3df3f807ab09eb0f53159b043a2e20e23" nocase ascii wide
                        $string16_SirepRAT_offensive_tool_keyword = "b718b5c185eb16e7276da28a376095a99f45007a953080ad759d3c839d0c520f" nocase ascii wide
                        $string17_SirepRAT_offensive_tool_keyword = "c9152451df19ff8cac70faf169055ea18b3b91eb105d722873b27da26af7b599" nocase ascii wide
                        $string18_SirepRAT_offensive_tool_keyword = "f463d3fbb08ed690d8d2429874bf6d36d9ac0d8e74a06439586fb4f49cbe8eac" nocase ascii wide
                        $string19_SirepRAT_offensive_tool_keyword = "fb785781e1e83a00582d1d3348c70249c256db03ddc4513f5b1a0853949b76ba" nocase ascii wide
                        $string20_SirepRAT_offensive_tool_keyword = /from\s\.SirepCommand\simport\sSirepCommand/ nocase ascii wide
                        $string21_SirepRAT_offensive_tool_keyword = /from\s\.SirepResult\simport\sSirepResult/ nocase ascii wide
                        $string22_SirepRAT_offensive_tool_keyword = "SafeBreach-Labs/SirepRAT" nocase ascii wide
                        $string23_SirepRAT_offensive_tool_keyword = "Sending Sirep payload" nocase ascii wide
                        $string24_SirepRAT_offensive_tool_keyword = /SirepRAT\.py\s/ nocase ascii wide
                        $string25_SirepRAT_offensive_tool_keyword = /SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_Slides\.pdf/ nocase ascii wide
                        $string26_SirepRAT_offensive_tool_keyword = /SirepRAT_RCE_as_SYSTEM_on_Windows_IoT_Core_White_Paper\.pdf/ nocase ascii wide
                        $string27_SirepRAT_offensive_tool_keyword = /SirepRAT\-2\.0\.0\.zip/ nocase ascii wide
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