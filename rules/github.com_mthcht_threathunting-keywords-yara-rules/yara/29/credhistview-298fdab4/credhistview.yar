rule credhistview
{
    meta:
        description = "Detection patterns for the tool 'credhistview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "credhistview"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\CredHistView\.cfg/ nocase ascii wide
                        $string2 = /\\credhistview\.lnk/ nocase ascii wide
                        $string3 = /\\credhistview\\/ nocase ascii wide
                        $string4 = /\>Don\sHO\sdon\.h\@free\.fr\</ nocase ascii wide
                        $string5 = /CredHistView\.exe/ nocase ascii wide
                        $string6 = /credhistview\.zip/ nocase ascii wide

    condition:
        any of them
}