rule rule_winPEAS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'winPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winPEAS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_winPEAS_offensive_tool_keyword = /\/winPEAS\.exe/ nocase ascii wide
                        $string2_winPEAS_offensive_tool_keyword = /\/winPEASany\.exe/ nocase ascii wide
                        $string3_winPEAS_offensive_tool_keyword = /\[winPEAS\.Program\]\:\:Main/ nocase ascii wide
                        $string4_winPEAS_offensive_tool_keyword = /\\winPEAS\.exe/ nocase ascii wide
                        $string5_winPEAS_offensive_tool_keyword = /\\winPEASany\.exe/ nocase ascii wide
                        $string6_winPEAS_offensive_tool_keyword = /winPEAS\.KnownFileCreds\.Browsers\.Chrome/ nocase ascii wide

    condition:
        any of them
}