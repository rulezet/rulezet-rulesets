rule ShuckNT
{
    meta:
        description = "Detection patterns for the tool 'ShuckNT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShuckNT"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/\/shuck\.sh/ nocase ascii wide
                        $string2 = /\/get\-shucking\.php/ nocase ascii wide
                        $string3 = /\/ShuckNT\.git/ nocase ascii wide
                        $string4 = /99\$1a7F1qr2HihoXfs\/56u5XMdpDZ83N6hW\/HI\=/ nocase ascii wide
                        $string5 = "pwned-passwords-ntlm" nocase ascii wide
                        $string6 = /shucknt\.php/ nocase ascii wide
                        $string7 = "ShuckNT-main" nocase ascii wide
                        $string8 = "wordlist-nthash-reversed" nocase ascii wide
                        $string9 = "yanncam/ShuckNT" nocase ascii wide

    condition:
        any of them
}