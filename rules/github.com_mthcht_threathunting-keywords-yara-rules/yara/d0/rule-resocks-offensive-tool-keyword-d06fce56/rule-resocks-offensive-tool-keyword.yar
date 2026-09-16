rule rule_resocks_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'resocks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "resocks"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_resocks_offensive_tool_keyword = /\$RESOCKS_KEY/ nocase ascii wide
                        $string2_resocks_offensive_tool_keyword = /\/resocks\s.{0,100}\s\-\-key\s/
                        $string3_resocks_offensive_tool_keyword = /\/resocks\.git/ nocase ascii wide
                        $string4_resocks_offensive_tool_keyword = "/resocks/releases/latest" nocase ascii wide
                        $string5_resocks_offensive_tool_keyword = /\/resocks_.{0,100}_Linux_x86_64\.tar\.gz/
                        $string6_resocks_offensive_tool_keyword = /\/resocks_.{0,100}_macOS_arm64\.tar\.gz/ nocase ascii wide
                        $string7_resocks_offensive_tool_keyword = /\/resocks_Darwin_x86_64\.tar\.gz/
                        $string8_resocks_offensive_tool_keyword = /\/resocks_Linux_.{0,100}\.tar\.gz/
                        $string9_resocks_offensive_tool_keyword = "0bd2acc669f0084786cd7df668e279e21e71556e9e927235a54f8bc6c1a27fa7" nocase ascii wide
                        $string10_resocks_offensive_tool_keyword = "29eb65e949707d372888fa09a691afd2d186e9ca6d97a5a7e89867468b675760" nocase ascii wide
                        $string11_resocks_offensive_tool_keyword = "2edd8774c18c9ba021f29ea142729d82bacf37ef2c58b45f43a7507785670c53" nocase ascii wide
                        $string12_resocks_offensive_tool_keyword = "358f4605b34480a8bc335e7ba588171d12a7c14c7219b2438c3594392b7c0468" nocase ascii wide
                        $string13_resocks_offensive_tool_keyword = "3c9fdaf1fc583a55cb67fbbd267e295773495cfb3e18dd0b6dfe4db8e9d82a44" nocase ascii wide
                        $string14_resocks_offensive_tool_keyword = "4a9652d48155a187a4c87e8d243f3b2514879927e9b8d56bd17e9b1c0d50da4b" nocase ascii wide
                        $string15_resocks_offensive_tool_keyword = "784f96fcd55e4e19e9178acc0b38fbb1536821a8ffdbf02a1606eec74ef82d4f" nocase ascii wide
                        $string16_resocks_offensive_tool_keyword = "8ef32f05998a4cc84237167458d42df34b3dc8534fb823ba909a8b2f76977eb7" nocase ascii wide
                        $string17_resocks_offensive_tool_keyword = "95ae5c9ab4faf301a44b0c4c0d98d88fd12191667b0f8c78cf933b32df3ff577" nocase ascii wide
                        $string18_resocks_offensive_tool_keyword = "a080c293df2577cc210e889abb0be13126606f159ff4b2c88323dc753f7b2c2c" nocase ascii wide
                        $string19_resocks_offensive_tool_keyword = "a352a6b52e5433a2dc19445287db1537ae6385dc6e1b2b11f53c222b14aae75d" nocase ascii wide
                        $string20_resocks_offensive_tool_keyword = "a992acc4b4e48dd6cdc389dcaf2291b330854f0b17369b1429590d3f824c3dfe" nocase ascii wide
                        $string21_resocks_offensive_tool_keyword = "abb8b93592a482b653c6d282ccad216f6cedc8bb50476aada7ee4b3562ecc9a4" nocase ascii wide
                        $string22_resocks_offensive_tool_keyword = "bc511e38827372f9bbfcd48fd448c51c0051f7cb64a91b2b4d0208a4dade3d22" nocase ascii wide
                        $string23_resocks_offensive_tool_keyword = "c9e4ebc73927d640543ab65574a94eed4d072e59d366ab37be405605914fa42d" nocase ascii wide
                        $string24_resocks_offensive_tool_keyword = /Connect\sback\sto\san\s.{0,100}\slistener\sand\srelay\sthe\sSOCKS5\straffic/ nocase ascii wide
                        $string25_resocks_offensive_tool_keyword = "d18597195b9b81b9e401547e4b630acf09ad39401bdcc8b5fa2e05e4677cf46f" nocase ascii wide
                        $string26_resocks_offensive_tool_keyword = "d2ea7a48b45df38e486ffe3757119d2257cd4b2a560ca67c463aff63e9a34a0d" nocase ascii wide
                        $string27_resocks_offensive_tool_keyword = "export RESOCKS_KEY=" nocase ascii wide
                        $string28_resocks_offensive_tool_keyword = "f108ce909b11c42406540ae67c339f22fd9842db9ecdc5765bcd2b35f5723198" nocase ascii wide
                        $string29_resocks_offensive_tool_keyword = "RedTeamPentesting/kbtls" nocase ascii wide
                        $string30_resocks_offensive_tool_keyword = "RedTeamPentesting/resocks" nocase ascii wide
                        $string31_resocks_offensive_tool_keyword = "resocks generate" nocase ascii wide
                        $string32_resocks_offensive_tool_keyword = "resocks listen" nocase ascii wide
                        $string33_resocks_offensive_tool_keyword = "resocks/proxyrelay" nocase ascii wide
                        $string34_resocks_offensive_tool_keyword = /resocks_Windows_x86_64\.zip/ nocase ascii wide
                        $string35_resocks_offensive_tool_keyword = "SOCKS5 server active" nocase ascii wide
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