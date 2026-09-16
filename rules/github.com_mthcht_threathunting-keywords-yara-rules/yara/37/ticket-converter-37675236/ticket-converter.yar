rule ticket_converter
{
    meta:
        description = "Detection patterns for the tool 'ticket_converter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ticket_converter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sticket_converter\.py/ nocase ascii wide
                        $string2 = /\.py.{0,1000}\.ccache\s.{0,1000}\.kirbi\s/ nocase ascii wide
                        $string3 = /\.py.{0,1000}\.kirbi\s.{0,1000}\.ccache/ nocase ascii wide
                        $string4 = /\/ticket_converter\.py/ nocase ascii wide
                        $string5 = /\\ticket_converter\.py/ nocase ascii wide

    condition:
        any of them
}