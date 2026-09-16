rule rule_dll_hijack_by_proxying_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dll-hijack-by-proxying' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dll-hijack-by-proxying"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dll_hijack_by_proxying_offensive_tool_keyword = "// Malicious payload should be implemented here" nocase ascii wide
                        $string2_dll_hijack_by_proxying_offensive_tool_keyword = /\/dll\-hijack\-by\-proxying\.git/ nocase ascii wide
                        $string3_dll_hijack_by_proxying_offensive_tool_keyword = /\\dll\-hijack\-by\-proxying/ nocase ascii wide
                        $string4_dll_hijack_by_proxying_offensive_tool_keyword = /\\dll\-hijack\-by\-proxying\-master/ nocase ascii wide
                        $string5_dll_hijack_by_proxying_offensive_tool_keyword = "tothi/dll-hijack-by-proxying" nocase ascii wide

    condition:
        any of them
}