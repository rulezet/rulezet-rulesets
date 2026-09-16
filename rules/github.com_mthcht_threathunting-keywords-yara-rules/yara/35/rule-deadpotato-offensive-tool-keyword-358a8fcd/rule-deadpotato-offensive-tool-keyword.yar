rule rule_DeadPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DeadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeadPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DeadPotato_offensive_tool_keyword = /\/DeadPotato\.git/ nocase ascii wide
                        $string2_DeadPotato_offensive_tool_keyword = "/releases/download/Binaries/DeadPotato" nocase ascii wide
                        $string3_DeadPotato_offensive_tool_keyword = /\\DeadPotato\\pipe\\epmapper/ nocase ascii wide
                        $string4_DeadPotato_offensive_tool_keyword = /\\GodPotato\\pipe\\epmapper/ nocase ascii wide
                        $string5_DeadPotato_offensive_tool_keyword = /\\Resources\\mimikatz\.exe/ nocase ascii wide
                        $string6_DeadPotato_offensive_tool_keyword = ">DeadPotato<" nocase ascii wide
                        $string7_DeadPotato_offensive_tool_keyword = "2AE886C3-3272-40BE-8D3C-EBAEDE9E61E1" nocase ascii wide
                        $string8_DeadPotato_offensive_tool_keyword = "3ef06f25d21583d9c1158704c593f3276a1056cf6d23f8c56d8dac84df5320de" nocase ascii wide
                        $string9_DeadPotato_offensive_tool_keyword = "92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50" nocase ascii wide
                        $string10_DeadPotato_offensive_tool_keyword = "99333bd2aadc9ebdbeb842981f1bb054f2102cdb94e77a0a8d7588cabaf70dc6" nocase ascii wide
                        $string11_DeadPotato_offensive_tool_keyword = "9cd007dd93a195546eec029470211689568df8c877fdc5faef1e03f942097a9b" nocase ascii wide
                        $string12_DeadPotato_offensive_tool_keyword = "9d1292d97f03943a54c41497f4b4e3186dea857a276f76954206e42f848fa30d" nocase ascii wide
                        $string13_DeadPotato_offensive_tool_keyword = "a1202bb8a90a635f6551b1733c4b777ee6abac7689dad8e7391e3ad01e3a370e" nocase ascii wide
                        $string14_DeadPotato_offensive_tool_keyword = "b32415b6a08d324394ac97c20a27b5f5bd2425f4f7caef7bf75b733c6fe5f2fb" nocase ascii wide
                        $string15_DeadPotato_offensive_tool_keyword = "c871b8811cc20f85aa417f598bd55d43d7ebac611c238c364c8ab41953efe321" nocase ascii wide
                        $string16_DeadPotato_offensive_tool_keyword = /deadpotato\.exe/ nocase ascii wide
                        $string17_DeadPotato_offensive_tool_keyword = /DeadPotato\-NET4\.exe/ nocase ascii wide
                        $string18_DeadPotato_offensive_tool_keyword = "ea36b8a42cc8ef052c4b58d29bdd20c5fe95dd8a025f8ac4728046891ef281bc" nocase ascii wide
                        $string19_DeadPotato_offensive_tool_keyword = /GodPotato\.exe/ nocase ascii wide
                        $string20_DeadPotato_offensive_tool_keyword = "lypd0/DeadPotato" nocase ascii wide
                        $string21_DeadPotato_offensive_tool_keyword = "ncacn_ip_tcp:fuck you !" nocase ascii wide
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