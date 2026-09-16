rule rule_ticket_converter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ticket_converter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ticket_converter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ticket_converter_offensive_tool_keyword = /\sticket_converter\.py/ nocase ascii wide
                        $string2_ticket_converter_offensive_tool_keyword = /\.py.{0,1000}\.ccache\s.{0,1000}\.kirbi\s/ nocase ascii wide
                        $string3_ticket_converter_offensive_tool_keyword = /\.py.{0,1000}\.kirbi\s.{0,1000}\.ccache/ nocase ascii wide
                        $string4_ticket_converter_offensive_tool_keyword = /\/ticket_converter\.py/ nocase ascii wide
                        $string5_ticket_converter_offensive_tool_keyword = /\\ticket_converter\.py/ nocase ascii wide

    condition:
        any of them
}