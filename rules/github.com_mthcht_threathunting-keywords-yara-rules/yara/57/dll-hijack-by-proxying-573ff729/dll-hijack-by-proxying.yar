rule dll_hijack_by_proxying
{
    meta:
        description = "Detection patterns for the tool 'dll-hijack-by-proxying' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dll-hijack-by-proxying"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "// Malicious payload should be implemented here" nocase ascii wide
                        $string2 = /\/dll\-hijack\-by\-proxying\.git/ nocase ascii wide
                        $string3 = /\\dll\-hijack\-by\-proxying/ nocase ascii wide
                        $string4 = /\\dll\-hijack\-by\-proxying\-master/ nocase ascii wide
                        $string5 = "tothi/dll-hijack-by-proxying" nocase ascii wide

    condition:
        any of them
}