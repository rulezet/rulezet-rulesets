rule rule_Net_GPPPassword_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Net-GPPPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Net-GPPPassword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Net_GPPPassword_offensive_tool_keyword = /\/Net\-GPPPassword\.git/ nocase ascii wide
                        $string2_Net_GPPPassword_offensive_tool_keyword = /Net\-GPPPassword\.cs/ nocase ascii wide
                        $string3_Net_GPPPassword_offensive_tool_keyword = /Net\-GPPPassword\.exe/ nocase ascii wide
                        $string4_Net_GPPPassword_offensive_tool_keyword = "Net-GPPPassword_dotNET" nocase ascii wide
                        $string5_Net_GPPPassword_offensive_tool_keyword = "Net-GPPPassword-master" nocase ascii wide
                        $string6_Net_GPPPassword_offensive_tool_keyword = "outflanknl/Net-GPPPassword" nocase ascii wide

    condition:
        any of them
}