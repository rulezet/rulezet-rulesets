rule Net_GPPPassword
{
    meta:
        description = "Detection patterns for the tool 'Net-GPPPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Net-GPPPassword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Net\-GPPPassword\.git/ nocase ascii wide
                        $string2 = /Net\-GPPPassword\.cs/ nocase ascii wide
                        $string3 = /Net\-GPPPassword\.exe/ nocase ascii wide
                        $string4 = "Net-GPPPassword_dotNET" nocase ascii wide
                        $string5 = "Net-GPPPassword-master" nocase ascii wide
                        $string6 = "outflanknl/Net-GPPPassword" nocase ascii wide

    condition:
        any of them
}