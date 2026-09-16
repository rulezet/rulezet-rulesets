rule rule_slip_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'slip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "slip"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_slip_offensive_tool_keyword = /\s\-\-archive\-type\star\s\-\-mass\-find\s.{0,1000}\s\-\-mass\-find\-mode\ssymlinks\sarchive/ nocase ascii wide
                        $string2_slip_offensive_tool_keyword = /\s\-\-archive\-type\szip\s\-\-symlinks\s\\"\.\.\/etc\/hosts.{0,1000}linkname\\"\sarchive\s\s/
                        $string3_slip_offensive_tool_keyword = /\sslip\.py\s/ nocase ascii wide
                        $string4_slip_offensive_tool_keyword = /\.\/slip\.py\s/
                        $string5_slip_offensive_tool_keyword = /\/path_traversal_dict\.txt/ nocase ascii wide
                        $string6_slip_offensive_tool_keyword = /\/slip\.git/ nocase ascii wide
                        $string7_slip_offensive_tool_keyword = /\/slip\-main\.zip/ nocase ascii wide
                        $string8_slip_offensive_tool_keyword = /\\path_traversal_dict\.txt/ nocase ascii wide
                        $string9_slip_offensive_tool_keyword = /\\slip\.py\s/ nocase ascii wide
                        $string10_slip_offensive_tool_keyword = /\\slip\-main\.zip/ nocase ascii wide
                        $string11_slip_offensive_tool_keyword = "0xless/slip" nocase ascii wide
                        $string12_slip_offensive_tool_keyword = /python3\sslip\.py/ nocase ascii wide
                        $string13_slip_offensive_tool_keyword = /slip.{0,1000}\s\-\-archive\-type\s.{0,1000}\s\-\-compression\s.{0,1000}\s\-\-paths\s.{0,1000}\s\-\-file\-content\s/ nocase ascii wide

    condition:
        any of them
}