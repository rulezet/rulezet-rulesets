rule rule_KCMTicketFormatter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KCMTicketFormatter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KCMTicketFormatter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KCMTicketFormatter_offensive_tool_keyword = "/KCMTicketFormatter"
                        $string2_KCMTicketFormatter_offensive_tool_keyword = /\\KCMTicketFormatter/ nocase ascii wide
                        $string3_KCMTicketFormatter_offensive_tool_keyword = /Format\sSSSD\sRaw\sKerberos\sPayloads\sinto\sCCACHE\sfiles\./ nocase ascii wide
                        $string4_KCMTicketFormatter_offensive_tool_keyword = /KCMTicketFormatter\.py/ nocase ascii wide

    condition:
        any of them
}