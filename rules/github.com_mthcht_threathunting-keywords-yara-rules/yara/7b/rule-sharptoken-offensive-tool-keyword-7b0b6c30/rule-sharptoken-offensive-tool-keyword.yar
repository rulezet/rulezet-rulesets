rule rule_SharpToken_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpToken' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpToken"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpToken_offensive_tool_keyword = /\sexecute\s.{0,100}NT\sAUTHORITY\\SYSTEM.{0,100}cmd\s\/c\s/ nocase ascii wide
                        $string2_SharpToken_offensive_tool_keyword = /\sexecute\sNT\sAUTHORITY\\SYSTEM.{0,100}\scmd\strue\sbypass/ nocase ascii wide
                        $string3_SharpToken_offensive_tool_keyword = "/SharpToken/releases/download/" nocase ascii wide
                        $string4_SharpToken_offensive_tool_keyword = /\]\sLeak\sof\scomplete\sPriv\stoken\ssuccessful\!/ nocase ascii wide
                        $string5_SharpToken_offensive_tool_keyword = "07249ebf1045b25fce113f88373e816cd382d2147540ec274a1b1a0356004c7b" nocase ascii wide
                        $string6_SharpToken_offensive_tool_keyword = "30cb4b65148413d62c04a83891b7dda36fb70d4699d02a5758e9122a833b8e73" nocase ascii wide
                        $string7_SharpToken_offensive_tool_keyword = "56d3be8ac6590cb5e593768aa36d4a0d6c39de5c96942e312876c3e0069edeae" nocase ascii wide
                        $string8_SharpToken_offensive_tool_keyword = "59c75b410227497fbe9522a50dae6b52db1a222f946064d796ac10b918e5e4e6" nocase ascii wide
                        $string9_SharpToken_offensive_tool_keyword = "894a784e-e04c-483c-a762-b6c03e744d0b" nocase ascii wide
                        $string10_SharpToken_offensive_tool_keyword = "894A784E-E04C-483C-A762-B6C03E744D0B" nocase ascii wide
                        $string11_SharpToken_offensive_tool_keyword = "8ae7a65345d809173343b02d58019e287e108d4688e483d761c89976e3ab2c9e" nocase ascii wide
                        $string12_SharpToken_offensive_tool_keyword = "9980d0e503ffda2d4e254f2039bb6c5d7534d107178a2b4d871685ce6a899c05" nocase ascii wide
                        $string13_SharpToken_offensive_tool_keyword = "BeichenDream/SharpToken" nocase ascii wide
                        $string14_SharpToken_offensive_tool_keyword = "c5486044f99bdf53ddbd6d45a22c38183f094a8c0db958c189c2b601d2b2b13e" nocase ascii wide
                        $string15_SharpToken_offensive_tool_keyword = /cmd\s\/c\swhoami.{0,100}\sbypass/ nocase ascii wide
                        $string16_SharpToken_offensive_tool_keyword = "f45212661e27ef359bff3c919d7f6ac16517484e650bab99eecc29866f021dcf" nocase ascii wide
                        $string17_SharpToken_offensive_tool_keyword = "f4cd930bac7a9c0ab246d0eda53e0d7b541d3cb206687e52c5f9389c53aa5098" nocase ascii wide
                        $string18_SharpToken_offensive_tool_keyword = "fd6af36ad90f3287d849c6542f3dacd29cc06cb01bdf618a2168d0968a757894" nocase ascii wide
                        $string19_SharpToken_offensive_tool_keyword = "SharpToken execute" nocase ascii wide
                        $string20_SharpToken_offensive_tool_keyword = /SharpToken.{0,100}\sadd_user/ nocase ascii wide
                        $string21_SharpToken_offensive_tool_keyword = /SharpToken.{0,100}\sdelete_user/ nocase ascii wide
                        $string22_SharpToken_offensive_tool_keyword = /SharpToken.{0,100}\senableUser\s/ nocase ascii wide
                        $string23_SharpToken_offensive_tool_keyword = /SharpToken.{0,100}\slist_token/ nocase ascii wide
                        $string24_SharpToken_offensive_tool_keyword = /SharpToken.{0,100}\stscon\s/ nocase ascii wide
                        $string25_SharpToken_offensive_tool_keyword = /SharpToken\.csproj/ nocase ascii wide
                        $string26_SharpToken_offensive_tool_keyword = /SharpToken\.exe/ nocase ascii wide
                        $string27_SharpToken_offensive_tool_keyword = /SharpToken\.git/ nocase ascii wide
                        $string28_SharpToken_offensive_tool_keyword = /SharpToken\-main\.zip/ nocase ascii wide
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