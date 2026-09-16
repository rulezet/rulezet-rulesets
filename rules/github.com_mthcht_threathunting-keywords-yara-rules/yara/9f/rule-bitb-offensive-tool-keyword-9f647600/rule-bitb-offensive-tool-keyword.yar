rule rule_bitb_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bitb' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitb"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bitb_offensive_tool_keyword = /\/BITB\.git/ nocase ascii wide
                        $string2_bitb_offensive_tool_keyword = "/BITB-main" nocase ascii wide
                        $string3_bitb_offensive_tool_keyword = /\\BITB\-main/ nocase ascii wide
                        $string4_bitb_offensive_tool_keyword = /bitb_server\/phishing\.ini/ nocase ascii wide
                        $string5_bitb_offensive_tool_keyword = "mrd0x/BITB" nocase ascii wide
                        $string6_bitb_offensive_tool_keyword = "XX-PHISHING-LINK-XX" nocase ascii wide

    condition:
        any of them
}