rule LTProxy
{
    meta:
        description = "Detection patterns for the tool 'LTProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LTProxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/\.ltproxy\.yml/
                        $string2 = /\/etc\/ltproxy\.yml/
                        $string3 = /\/LTProxy\.git/
                        $string4 = /\/tmp\/\.ltproxy_proxychains_/
                        $string5 = /\\LTProxy\-main/
                        $string6 = "ac5f344727467b6ad9743b8ffa2646ed73180dbdb97224feec6c54c5160a1984"
                        $string7 = /ipt2socks\s\-R\s\-n\s9999\s\-j\s50\s\-u\s.{0,1000}\s\-s\s.{0,1000}\s\-l\s/
                        $string8 = "L-codes/LTProxy"
                        $string9 = "ltproxy restart"
                        $string10 = "ltproxy start"
                        $string11 = "ltproxy stop"

    condition:
        any of them
}