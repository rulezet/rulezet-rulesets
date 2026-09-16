rule rule_credhistview_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'credhistview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "credhistview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_credhistview_offensive_tool_keyword = /\\CredHistView\.cfg/ nocase ascii wide
                        $string2_credhistview_offensive_tool_keyword = /\\credhistview\.lnk/ nocase ascii wide
                        $string3_credhistview_offensive_tool_keyword = /\\credhistview\\/ nocase ascii wide
                        $string4_credhistview_offensive_tool_keyword = /\>Don\sHO\sdon\.h\@free\.fr\</ nocase ascii wide
                        $string5_credhistview_offensive_tool_keyword = /CredHistView\.exe/ nocase ascii wide
                        $string6_credhistview_offensive_tool_keyword = /credhistview\.zip/ nocase ascii wide

    condition:
        any of them
}