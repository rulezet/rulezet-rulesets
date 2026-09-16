rule slip
{
    meta:
        description = "Detection patterns for the tool 'slip' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "slip"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-archive\-type\star\s\-\-mass\-find\s.{0,1000}\s\-\-mass\-find\-mode\ssymlinks\sarchive/ nocase ascii wide
                        $string2 = /\s\-\-archive\-type\szip\s\-\-symlinks\s\\"\.\.\/etc\/hosts.{0,1000}linkname\\"\sarchive\s\s/
                        $string3 = /\sslip\.py\s/ nocase ascii wide
                        $string4 = /\.\/slip\.py\s/
                        $string5 = /\/path_traversal_dict\.txt/ nocase ascii wide
                        $string6 = /\/slip\.git/ nocase ascii wide
                        $string7 = /\/slip\-main\.zip/ nocase ascii wide
                        $string8 = /\\path_traversal_dict\.txt/ nocase ascii wide
                        $string9 = /\\slip\.py\s/ nocase ascii wide
                        $string10 = /\\slip\-main\.zip/ nocase ascii wide
                        $string11 = "0xless/slip" nocase ascii wide
                        $string12 = /python3\sslip\.py/ nocase ascii wide
                        $string13 = /slip.{0,1000}\s\-\-archive\-type\s.{0,1000}\s\-\-compression\s.{0,1000}\s\-\-paths\s.{0,1000}\s\-\-file\-content\s/ nocase ascii wide

    condition:
        any of them
}