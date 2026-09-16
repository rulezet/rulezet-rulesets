rule rule_ShuckNT_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ShuckNT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShuckNT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ShuckNT_offensive_tool_keyword = /\/\/shuck\.sh/ nocase ascii wide
                        $string2_ShuckNT_offensive_tool_keyword = /\/get\-shucking\.php/ nocase ascii wide
                        $string3_ShuckNT_offensive_tool_keyword = /\/ShuckNT\.git/ nocase ascii wide
                        $string4_ShuckNT_offensive_tool_keyword = /99\$1a7F1qr2HihoXfs\/56u5XMdpDZ83N6hW\/HI\=/ nocase ascii wide
                        $string5_ShuckNT_offensive_tool_keyword = "pwned-passwords-ntlm" nocase ascii wide
                        $string6_ShuckNT_offensive_tool_keyword = /shucknt\.php/ nocase ascii wide
                        $string7_ShuckNT_offensive_tool_keyword = "ShuckNT-main" nocase ascii wide
                        $string8_ShuckNT_offensive_tool_keyword = "wordlist-nthash-reversed" nocase ascii wide
                        $string9_ShuckNT_offensive_tool_keyword = "yanncam/ShuckNT" nocase ascii wide

    condition:
        any of them
}