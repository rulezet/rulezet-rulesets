rule winPEAS
{
    meta:
        description = "Detection patterns for the tool 'winPEAS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winPEAS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/winPEAS\.exe/ nocase ascii wide
                        $string2 = /\/winPEASany\.exe/ nocase ascii wide
                        $string3 = /\[winPEAS\.Program\]\:\:Main/ nocase ascii wide
                        $string4 = /\\winPEAS\.exe/ nocase ascii wide
                        $string5 = /\\winPEASany\.exe/ nocase ascii wide
                        $string6 = /winPEAS\.KnownFileCreds\.Browsers\.Chrome/ nocase ascii wide

    condition:
        any of them
}