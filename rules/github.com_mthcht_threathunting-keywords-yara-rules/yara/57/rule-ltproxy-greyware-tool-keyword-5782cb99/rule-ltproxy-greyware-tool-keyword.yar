rule rule_LTProxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LTProxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LTProxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_LTProxy_greyware_tool_keyword = /\/\.ltproxy\.yml/
                        $string2_LTProxy_greyware_tool_keyword = /\/etc\/ltproxy\.yml/
                        $string3_LTProxy_greyware_tool_keyword = /\/LTProxy\.git/
                        $string4_LTProxy_greyware_tool_keyword = /\/tmp\/\.ltproxy_proxychains_/
                        $string5_LTProxy_greyware_tool_keyword = /\\LTProxy\-main/
                        $string6_LTProxy_greyware_tool_keyword = "ac5f344727467b6ad9743b8ffa2646ed73180dbdb97224feec6c54c5160a1984"
                        $string7_LTProxy_greyware_tool_keyword = /ipt2socks\s\-R\s\-n\s9999\s\-j\s50\s\-u\s.{0,1000}\s\-s\s.{0,1000}\s\-l\s/
                        $string8_LTProxy_greyware_tool_keyword = "L-codes/LTProxy"
                        $string9_LTProxy_greyware_tool_keyword = "ltproxy restart"
                        $string10_LTProxy_greyware_tool_keyword = "ltproxy start"
                        $string11_LTProxy_greyware_tool_keyword = "ltproxy stop"

    condition:
        any of them
}