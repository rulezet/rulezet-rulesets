rule rule_TGT_Monitor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TGT_Monitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TGT_Monitor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TGT_Monitor_offensive_tool_keyword = /\sTGT_Monitor\.ps1/ nocase ascii wide
                        $string2_TGT_Monitor_offensive_tool_keyword = /\/TGT_Monitor\.git/ nocase ascii wide
                        $string3_TGT_Monitor_offensive_tool_keyword = /\/TGT_Monitor\.ps1/ nocase ascii wide
                        $string4_TGT_Monitor_offensive_tool_keyword = /\\TGT_Monitor\.ps1/ nocase ascii wide
                        $string5_TGT_Monitor_offensive_tool_keyword = "1004ed17f2164c6dd249f7d640e8c8250e6c47d9e4d2c8748becb05591a8539b" nocase ascii wide
                        $string6_TGT_Monitor_offensive_tool_keyword = "Get-AesKeyFromPassphrase" nocase ascii wide
                        $string7_TGT_Monitor_offensive_tool_keyword = "Leo4j/TGT_Monitor" nocase ascii wide
                        $string8_TGT_Monitor_offensive_tool_keyword = "TGT_Monitor -EncryptionKey " nocase ascii wide

    condition:
        any of them
}